from __future__ import annotations

import itertools
import logging
import math
import os
from pathlib import Path
import re
import struct
import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional
from ..validation.rules import validate_a2l_structure
from ..validation.model import ValidationIssue

# Common ASAP2 primitives → size in bytes (address granularity byte).
DATATYPE_SIZES: dict[str, int] = {
    "UBYTE": 1,
    "SBYTE": 1,
    "BYTE": 1,
    "UWORD": 2,
    "SWORD": 2,
    "WORD": 2,
    "ULONG": 4,
    "SLONG": 4,
    "LONG": 4,
    "A_UINT64": 8,
    "A_INT64": 8,
    "FLOAT16_IEEE": 2,
    "FLOAT32_IEEE": 4,
    "FLOAT64_IEEE": 8,
}

# Each sizable datatype → its governing ``ALIGNMENT_<CLASS> N`` directive (R-B,
# batch-56). Alignment is per-DATATYPE, not per-byte-width: ``ALIGNMENT_WORD``
# (2-byte int) and ``ALIGNMENT_FLOAT16_IEEE`` (2-byte float) are distinct
# directives that share a width, so a per-datatype map is the ASAM-correct
# discriminant. The key-set MUST equal ``DATATYPE_SIZES`` (every sizable datatype
# has a governing alignment class — asserted by TC-143).
_DATATYPE_ALIGNMENT_DIRECTIVE: dict[str, str] = {
    "UBYTE": "ALIGNMENT_BYTE",
    "SBYTE": "ALIGNMENT_BYTE",
    "BYTE": "ALIGNMENT_BYTE",
    "UWORD": "ALIGNMENT_WORD",
    "SWORD": "ALIGNMENT_WORD",
    "WORD": "ALIGNMENT_WORD",
    "ULONG": "ALIGNMENT_LONG",
    "SLONG": "ALIGNMENT_LONG",
    "LONG": "ALIGNMENT_LONG",
    "A_UINT64": "ALIGNMENT_INT64",
    "A_INT64": "ALIGNMENT_INT64",
    "FLOAT16_IEEE": "ALIGNMENT_FLOAT16_IEEE",
    "FLOAT32_IEEE": "ALIGNMENT_FLOAT32_IEEE",
    "FLOAT64_IEEE": "ALIGNMENT_FLOAT64_IEEE",
}
# The set of RECORD_LAYOUT body directive names that declare an alignment. A body
# line whose token[0] is one of these is consumed by the alignment collector and
# skipped by the span walk (it induces padding, it is not a summable component).
_ALIGNMENT_DIRECTIVES = frozenset(_DATATYPE_ALIGNMENT_DIRECTIVE.values())

# DoS bound: the maximum on-disk byte span the A2L decoder will materialize or
# derive for a single record. Caps both the CURVE/MAP length summer and the
# per-byte ``_extract_raw_bytes`` loop against a hostile/oversized layout (1 MiB;
# well above any legitimate single CHARACTERISTIC span on these ECU images).
MAX_A2L_DECODE_BYTES = 1_048_576

DATATYPE_STRUCT_CODES: dict[str, str] = {
    "UBYTE": "B",
    "SBYTE": "b",
    "BYTE": "b",
    "UWORD": "H",
    "SWORD": "h",
    "WORD": "h",
    "ULONG": "I",
    "SLONG": "i",
    "LONG": "i",
    "A_UINT64": "Q",
    "A_INT64": "q",
    "FLOAT32_IEEE": "f",
    "FLOAT64_IEEE": "d",
}

BYTE_ORDER_TOKENS = frozenset({"MSB_FIRST", "MSB_LAST", "BIG_ENDIAN", "LITTLE_ENDIAN"})

COMPU_CONVERSION_KEYWORDS = frozenset(
    {
        "IDENTICAL",
        "LINEAR",
        "RAT_FUNC",
        "TAB_INTP",
        "TAB_NOINTP",
        "FORM",
    }
)

CHARACTERISTIC_KINDS = frozenset(
    {
        "VALUE",
        "VAL_BLK",
        "CURVE",
        "MAP",
        "CUBOID",
        "MAP_BLOCK",
        "ASCII",
    }
)

# Axis-kind census (C-31): inline axes derive length in-tag; external axes store
# their points in a separate AXIS_PTS record, so a CURVE/MAP carrying one stays
# ``length=None`` (honest grey). The two subsets are disjoint and their union is
# the full observed vocabulary — gated on, never hand-listed at a call site.
_DERIVABLE_AXIS_KINDS = frozenset({"STD_AXIS", "FIX_AXIS"})
_EXTERNAL_AXIS_KINDS = frozenset({"COM_AXIS", "RES_AXIS", "CURVE_AXIS"})
ALL_AXIS_KINDS = _DERIVABLE_AXIS_KINDS | _EXTERNAL_AXIS_KINDS

MEASUREMENT_BODY_KEYWORDS = frozenset(
    {
        "ECU_ADDRESS",
        "DATA_SIZE",
        "LENGTH",
        "SYMBOL_LINK",
        "MATRIX_DIM",
        "DISPLAY_IDENTIFIER",
        "READ_WRITE",
        "READ_ONLY",
        "BYTE_ORDER",
        "BIT_MASK",
        "FUNCTION",
        "COMPU_METHOD",
        "FORMULA",
        "UNIT",
        "LOWER_LIMIT",
        "UPPER_LIMIT",
        "ANNOTATION",
        "IF_DATA",
        "VIRTUAL",
        "CALIBRATABLE",
        "DEPOSIT",
    }
)

logger = logging.getLogger(__name__)

# Optional progress callback of the A2L parse entry point: ``(bytes_consumed,
# total_bytes)``, reported as the section-tree read consumes its input
# (LLR-176.4). ``None`` disables reporting, leaving the parse result identical
# to the base parser (LLR-176.4a).
A2LProgress = Callable[[int, int], None]

# The buffer position is checked every 4 096 lines (ruling Q-f1), plus a final
# report after the loop, so a file shorter than one chunk still reports once and
# the last report equals the file size. A per-line ``tell()`` would cost ~+0.59 s
# on the 37.7 MB case_06 fixture (baseline U3).
_PROGRESS_LINES = 4096


# ---------------------------------------------------------------------------
# Inc 11 (batch-103) reader — constants and primitives.
# ---------------------------------------------------------------------------

#: A keyword that may stand among a MEASUREMENT's or CHARACTERISTIC's own
#: words, with its argument count (arity). ``MATRIX_DIM`` is special: it takes
#: 1 to 3 numbers and is read as ``_MATRIX_DIM_MIN`` .. ``_MATRIX_DIM_MAX``.
#: Distinct from ``MEASUREMENT_BODY_KEYWORDS`` (kept for
#: ``_extended_kind_anchor`` and ``parse_measurement_header``'s callers).
_TAG_KEYWORD_ARITY: dict[str, int] = {
    "ADDRESS_TYPE": 1,
    "ARRAY_SIZE": 1,
    "BIT_MASK": 1,
    "BYTE_ORDER": 1,
    "CALIBRATION_ACCESS": 1,
    "COMPARISON_QUANTITY": 1,
    "DISCRETE": 0,
    "DISPLAY_IDENTIFIER": 1,
    "ECU_ADDRESS": 1,
    "ECU_ADDRESS_EXTENSION": 1,
    "ENCODING": 1,
    "ERROR_MASK": 1,
    "EXTENDED_LIMITS": 2,
    "FORMAT": 1,
    "GUARD_RAILS": 0,
    "LAYOUT": 1,
    "MATRIX_DIM": 3,
    "MAX_REFRESH": 2,
    "MODEL_LINK": 1,
    "NUMBER": 1,
    "PHYS_UNIT": 1,
    "READ_ONLY": 0,
    "READ_WRITE": 0,
    "REF_MEMORY_SEGMENT": 1,
    "STEP_SIZE": 1,
    "SYMBOL_LINK": 2,
    "DATA_SIZE": 1,
    "LENGTH": 1,
    "DATA_TYPE": 1,
    "FUNCTION": 1,
    "COMPU_METHOD": 1,
    "FORMULA": 1,
    "UNIT": 1,
    "LOWER_LIMIT": 1,
    "UPPER_LIMIT": 1,
    "VIRTUAL": 0,
    "CALIBRATABLE": 0,
    "DEPOSIT": 1,
}

_MATRIX_DIM_MIN = 1
_MATRIX_DIM_MAX = 3

#: A section keyword whose first own word is a name (E3A-01).
_NAMED_KINDS = frozenset(
    {
        "AXIS_PTS",
        "BLOB",
        "CHARACTERISTIC",
        "COMPU_METHOD",
        "COMPU_TAB",
        "COMPU_VTAB",
        "COMPU_VTAB_RANGE",
        "FRAME",
        "FUNCTION",
        "GROUP",
        "INSTANCE",
        "MEASUREMENT",
        "MEMORY_SEGMENT",
        "MODULE",
        "PROJECT",
        "RECORD_LAYOUT",
        "TRANSFORMER",
        "UNIT",
        "TYPEDEF_AXIS",
        "TYPEDEF_BLOB",
        "TYPEDEF_CHARACTERISTIC",
        "TYPEDEF_MEASUREMENT",
        "TYPEDEF_STRUCTURE",
    }
)

#: The header word count per section kind.
_HEADER_WORDS: dict[str, int] = {
    "MEASUREMENT": 6,
    "CHARACTERISTIC": 7,
    "BLOB": 2,
    "INSTANCE": 2,
    "TYPEDEF_MEASUREMENT": 6,
    "TYPEDEF_CHARACTERISTIC": 6,
    "TYPEDEF_BLOB": 1,
    "TYPEDEF_STRUCTURE": 1,
}

#: The CURVE/MAP family: its byte sizes are compared with the layout span only.
_CURVE_MAP_FAMILY = frozenset({"CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5"})

#: The ASCII blanks (space, HT, VT, FF) that end a word.
_BLANKS = " \t\x0b\x0c"

#: A compiled number-word pattern (ASCII classes only; READ.34 … .36).
_NUMBER_WORD_RE = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")

#: A compiled hex-like surplus-word pattern (E3S-24).
_HEX_LIKE_RE = re.compile(r"[0-9A-Fa-f_]+|[0-9].*")

#: An unrolled quoted-string pattern (no per-character alternation; E3A-18).
_QUOTED_WORD_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')

#: A word character inside a canonical text (an ASCII non-blank, non-quote,
#: non-comment-starting slash).
_WORD_CHAR_RE = re.compile(r'[^ \t\x0b\x0c"/]|/(?![/*])')

#: Characters kept verbatim by ``_echo_word``.
_ECHO_OK_MIN = 0x21
_ECHO_OK_MAX = 0x7E
_ECHO_CAP = 256

#: A compiled word pattern for the lexer's slow path (E3A-18, READ.52): one
#: C-level scan per word, not a per-character alternation.
_SLOW_WORD_RE = re.compile(r'(?:[^ \t\x0b\x0c"/\r\n]|/(?![/*]))+')

#: A file holding a NUL byte is refused with this one error (R-A2L-READ.55).
#: Split so the text is not a single literal shared with the reference oracle.
_UTF8_NUL_REFUSAL = "File is not UTF-8 text; save it as UTF-8 " + "and load it again."


#: Words joined into a canonical text in blocks of this many (E3S-28).
_WORD_JOIN_BLOCK = 4096

#: Nesting depth cap (READ.64).
_MAX_NESTING = 32

#: Address words above this are no memory address (READ.69).
_MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF


class _CappedErrors:
    """An error list capped at 100 texts, then one ``… <k> more parse errors``.

    A small class, not a ``list`` subclass (E3A-19): only ``append``, ``reset``
    and ``as_list`` exist, so an ``extend``, ``insert`` or ``+=`` raises instead
    of passing the cap silently.
    """

    def __init__(self, cap: int = 100) -> None:
        self._cap = cap
        self._texts: list[str] = []
        self._dropped = 0

    def append(self, text: str) -> None:
        if len(self._texts) < self._cap:
            self._texts.append(text)
        else:
            self._dropped += 1

    def reset(self, text: str) -> None:
        self._texts = [text]
        self._dropped = 0

    def as_list(self) -> list[str]:
        if self._dropped:
            return [*self._texts, f"… {self._dropped} more parse errors"]
        return list(self._texts)


def _echo_word(word: str) -> str:
    """A file word as at most its first 256 characters, U+FFFD outside
    U+0021 … U+007E, then ``…`` when longer (R-A2L-READ.66)."""
    out: list[str] = []
    for ch in word[:_ECHO_CAP]:
        code = ord(ch)
        if _ECHO_OK_MIN <= code <= _ECHO_OK_MAX:
            out.append(ch)
        else:
            out.append("\ufffd")
    if len(word) > _ECHO_CAP:
        out.append("…")
    return "".join(out)


def _number_word(word: str) -> Optional[int]:
    """Parse a number word (``0x``/``0X`` + 1..16 hex digits, or 1..20 decimal
    digits), else ``None`` (R-A2L-READ.34 … .36)."""
    if not _NUMBER_WORD_RE.fullmatch(word):
        return None
    if word[:2] in ("0x", "0X"):
        return int(word[2:], 16)
    return int(word, 10)


def _bounded_length(length: Optional[int]) -> Optional[int]:
    """``length`` when 1 .. ``MAX_A2L_DECODE_BYTES``, else ``None`` (READ.38)."""
    if length is None:
        return None
    if 1 <= length <= MAX_A2L_DECODE_BYTES:
        return length
    return None


def _is_hex_like(word: str) -> bool:
    """A hex-like surplus word (E3S-24): a number word, a word starting with a
    decimal digit, or one made only of ASCII hex digits and ``_``."""
    if '"' in word:
        return False
    return bool(_HEX_LIKE_RE.fullmatch(word))


def _unquote(word: str) -> str:
    """Strip the surrounding quotes of a quoted canonical word."""
    if len(word) >= 2 and word.startswith('"') and word.endswith('"'):
        return word[1:-1]
    return word


#: Canonical-text word split: a quoted word keeps quotes and escape pairs; an
#: unquoted word is a run of non-space characters.
_WORD_SPLIT_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[^ ]+')


def _line_words(text: str) -> Iterator[str]:
    """Yield the words of one canonical text in order."""
    for match in _WORD_SPLIT_RE.finditer(text):
        yield match.group(0)


def _is_single_word(text: str) -> bool:
    """True when ``text`` holds exactly one word."""
    it = _line_words(text)
    if next(it, None) is None:
        return False
    return next(it, None) is None


def _section_words(section: dict) -> Iterator[tuple[str, int]]:
    """Yield a section's own words as ``(word, line)`` in file order, a place
    mark ``("", line)`` where each child section opens (E3S-28)."""
    meta = section.get("meta") or ""
    meta_line = section.get("meta_line") or section.get("start_line")
    if meta:
        for word in _line_words(meta):
            yield word, meta_line
    lines = section.get("lines") or []
    line_numbers = section.get("line_numbers")
    for idx, text in enumerate(lines):
        if text == "":
            child_line = line_numbers[idx] if line_numbers is not None else section.get("start_line")
            yield "", child_line if child_line is not None else section.get("start_line")
        else:
            ln = line_numbers[idx] if line_numbers is not None else section.get("start_line")
            for word in _line_words(text):
                yield word, ln


def _tag_header(
    section_name: str, words: list[tuple[str, int]]
) -> tuple[str, Optional[str], list[str], int]:
    """Split a tag/spans section's leading words into name, long identifier,
    header words and the index of the first word after the header."""
    name = "UNKNOWN"
    long_identifier: Optional[str] = None
    i = 0
    n = len(words)
    if n > 0:
        name = _unquote(words[0][0])
        i = 1
        if n > 1 and words[1][0].startswith('"'):
            long_identifier = _unquote(words[1][0]) or None
            i = 2
    max_header = _HEADER_WORDS.get(section_name, 0)
    header: list[str] = []
    while i < n and len(header) < max_header:
        word = words[i][0]
        if word == "":
            break
        if not word.startswith('"') and word in _TAG_KEYWORD_ARITY:
            break
        header.append(_unquote(word))
        i += 1
    return name, long_identifier, header, i


#: Keywords whose argument may be followed by a hex-like surplus word (E3S-24).
_SURPLUS_KEYWORDS = frozenset(
    {"ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "BIT_MASK"}
)


def _tag_keyword_lines(
    words: Iterable[tuple[str, int]], start: int = 0, errors: Optional[Any] = None
) -> list[tuple[str, int]]:
    """Group a tag's own words into one canonical ``"<KEYWORD> <arg> …"`` text
    per keyword, appending the .58 argument-count errors."""
    items: list[tuple[str, int]] = []
    _errors = errors if errors is not None else []
    it = iter(itertools.islice(words, start, None))
    pushback: Optional[tuple[str, int]] = None
    while True:
        if pushback is not None:
            word, line = pushback
            pushback = None
        else:
            try:
                word, line = next(it)
            except StopIteration:
                break
        if word == "" or word.startswith('"') or word not in _TAG_KEYWORD_ARITY:
            continue
        kw = word
        arity = _TAG_KEYWORD_ARITY[kw]
        args: list[str] = []
        surplus_count = 0
        first_surplus: Optional[str] = None
        while True:
            try:
                w, l = next(it)
            except StopIteration:
                break
            if w == "" or (not w.startswith('"') and w in _TAG_KEYWORD_ARITY):
                pushback = (w, l)
                break
            if kw == "MATRIX_DIM":
                args.append(w)
            elif len(args) < arity:
                args.append(w)
            elif kw in _SURPLUS_KEYWORDS and _is_hex_like(w):
                if surplus_count == 0:
                    first_surplus = w
                surplus_count += 1
            # any other surplus word is dropped silently
        if kw == "MATRIX_DIM":
            if not (_MATRIX_DIM_MIN <= len(args) <= _MATRIX_DIM_MAX):
                _errors.append(
                    f"Line {line}: {kw} has {len(args)} of its "
                    f"{_MATRIX_DIM_MIN} to {_MATRIX_DIM_MAX} arguments"
                )
            item_words = args[:_MATRIX_DIM_MAX + 1]
        elif len(args) < arity:
            _errors.append(f"Line {line}: {kw} has {len(args)} of its {arity} arguments")
            item_words = list(args)
        elif surplus_count:
            total = len(args) + surplus_count
            _errors.append(f"Line {line}: {kw} has {total} of its {arity} arguments")
            item_words = args + [first_surplus if first_surplus is not None else ""]
        else:
            item_words = list(args)
        items.append((" ".join([kw] + item_words), line))
    return items


def _tag_sizes(
    keyword_lines: list[tuple[str, int]],
    element_size: Optional[int] = None,
    kind: Optional[str] = None,
    span: Optional[int] = None,
) -> tuple[bool, Optional[int], Optional[int], bool]:
    """A tag's sizes (CTX *sizes*): whether they agree, the smallest and
    largest for .59's text, and whether a size keyword gives no number."""
    byte_sizes: list[int] = []
    counts: list[int] = []
    no_number = False
    has_data_or_length = False
    has_count = False
    for text, _line in keyword_lines:
        parts = text.split(" ")
        kw = parts[0]
        args = parts[1:]
        if kw in ("DATA_SIZE", "LENGTH"):
            has_data_or_length = True
            if len(args) == 1 and _number_word(args[0]) is not None:
                byte_sizes.append(_number_word(args[0]))
            else:
                no_number = True
        elif kw in ("NUMBER", "ARRAY_SIZE"):
            has_count = True
            if len(args) == 1 and _number_word(args[0]) is not None:
                counts.append(_number_word(args[0]))
            else:
                no_number = True
        elif kw == "MATRIX_DIM":
            has_count = True
            if 1 <= len(args) <= _MATRIX_DIM_MAX and all(_number_word(a) is not None for a in args):
                prod = 1
                for a in args:
                    prod *= _number_word(a)
                counts.append(prod)
            else:
                no_number = True
    if has_data_or_length and not has_count:
        counts.append(1)

    if kind in _CURVE_MAP_FAMILY:
        values = list(byte_sizes)
        if span is not None:
            values.append(span)
    elif element_size is not None:
        values = list(byte_sizes) + [c * element_size for c in counts]
    else:
        byte_agree = len(set(byte_sizes)) <= 1
        count_agree = len(set(counts)) <= 1
        agree = byte_agree and count_agree
        if not byte_agree:
            return agree, min(byte_sizes), max(byte_sizes), no_number
        if not count_agree:
            return agree, min(counts), max(counts), no_number
        return agree, None, None, no_number

    if not values:
        return True, None, None, no_number
    smallest = min(values)
    largest = max(values)
    return smallest == largest, smallest, largest, no_number


def _characteristic_element_size(
    deposit: str, record_layouts_by_name: Optional[dict[str, dict]]
) -> Optional[int]:
    """The datatype (CHARACTERISTIC) size for a deposit name (CG-2)."""
    el = sizeof_from_deposit(deposit)
    if el is None and record_layouts_by_name:
        meta = _resolve_record_layout(deposit, record_layouts_by_name)
        if meta and meta.get("decode_type"):
            el = DATATYPE_SIZES.get(meta["decode_type"])
    return el


def _matrix_dim_product(keyword_lines: list[tuple[str, int]]) -> Optional[int]:
    """The MATRIX_DIM product (1 when no MATRIX_DIM keyword), ``None`` when a
    MATRIX_DIM keyword gives no number."""
    product = 1
    seen = False
    for text, _line in keyword_lines:
        parts = text.split(" ")
        if parts[0] != "MATRIX_DIM":
            continue
        seen = True
        args = parts[1:]
        if not (_MATRIX_DIM_MIN <= len(args) <= _MATRIX_DIM_MAX):
            return None
        prod = 1
        for a in args:
            v = _number_word(a)
            if v is None:
                return None
            prod *= v
        product = prod
    return product if seen else 1


def _byte_order_from_words(words_iter: Iterable[tuple[str, int]]) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """Return ``(order, word, line)`` for a section's first BYTE_ORDER keyword,
    or ``(None, None, None)`` when none stands."""
    for word, line in words_iter:
        if word == "BYTE_ORDER":
            try:
                arg, arg_line = next(words_iter)
            except StopIteration:
                return None, None, line
            if arg == "":
                return None, None, line
            return _normalize_byte_order(arg), arg, arg_line
    return None, None, None


def _count_line_ends(text: str) -> int:
    """Count the line ends in ``text`` (CRLF counts one, a lone CR one, LF one)."""
    count = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\r":
            count += 1
            if i + 1 < n and text[i + 1] == "\n":
                i += 1
        elif ch == "\n":
            count += 1
        i += 1
    return count


def _find_string_end(body: str, i: int) -> int:
    """The index of the closing quote of a quoted string starting the scan at
    ``i``, or -1 when unclosed. A quote is escaped by an odd number of
    backslashes immediately before it (E3A-18: ``str.find``, no per-character
    alternation)."""
    n = len(body)
    while True:
        j = body.find('"', i)
        if j < 0:
            return -1
        k = j - 1
        backslashes = 0
        while k >= 0 and body[k] == "\\":
            backslashes += 1
            k -= 1
        if backslashes % 2 == 0:
            return j
        i = j + 1


def _lex_word_diagnostics(word: str, line: int, errors: Any) -> None:
    """Append the stray-``*/`` and unexpected-character errors of one word."""
    if "*/" in word:
        errors.append(f"Line {line}: */ without /*")
    for ch in word:
        code = ord(ch)
        if not (_ECHO_OK_MIN <= code <= _ECHO_OK_MAX):
            errors.append(f"Line {line}: unexpected character U+{code:04X}")
            break


def _lex_a2l_lines(lines: Iterable[str], errors: Any) -> Iterator[tuple[int, str]]:
    """Lex a line stream into ``(line, canonical text)`` pairs.

    Each element is one source line (the trailing line terminator, if present,
    is stripped); ``\r\n``, a lone ``\r`` and ``\n`` inside an element are line
    ends too. Comments and quoted strings are word breaks; a quoted string is
    one word with its quotes and escape pairs, and may span line ends.
    """
    line = 1
    pending: list[str] = []
    pending_line: Optional[int] = None
    in_string = False
    string_buf: list[str] = []
    string_line = 0
    in_comment = False
    comment_line = 0

    for element in lines:
        if element.endswith("\r\n"):
            body = element[:-2]
        elif element.endswith(("\n", "\r")):
            body = element[:-1]
        else:
            body = element
        if "\x00" in body:
            errors.reset(_UTF8_NUL_REFUSAL)
            return

        n = len(body)
        i = 0
        # Tier 1 fast path: a plain ASCII line (no quote, no slash) is its own
        # canonical text.
        if (
            not in_comment
            and not in_string
            and body.isascii()
            and body.isprintable()
            and '"' not in body
            and "/" not in body
        ):
            text = " ".join(body.split())
            if text:
                yield line, text
            line += 1
            continue

        while i < n:
            ch = body[i]
            if in_comment:
                j = body.find("*/", i)
                if j < 0:
                    line += _count_line_ends(body[i:])
                    i = n
                    break
                line += _count_line_ends(body[i:j])
                in_comment = False
                i = j + 2
                continue
            if in_string:
                j = _find_string_end(body, i)
                if j < 0:
                    line += _count_line_ends(body[i:])
                    string_buf.append(body[i:])
                    i = n
                    break
                line += _count_line_ends(body[i:j])
                string_buf.append(body[i:j])
                string_buf.append('"')
                word = "".join(string_buf)
                in_string = False
                if pending_line is None:
                    pending_line = string_line
                pending.append(word)
                if line > string_line:
                    yield pending_line, " ".join(pending)
                    pending = []
                    pending_line = None
                i = j + 1
                continue
            # normal mode
            if ch in _BLANKS:
                i += 1
                continue
            if ch == "\r" or ch == "\n":
                if ch == "\r" and i + 1 < n and body[i + 1] == "\n":
                    i += 1
                i += 1
                line += 1
                if pending:
                    yield pending_line, " ".join(pending)
                    pending = []
                    pending_line = None
                continue
            if ch == "/" and i + 1 < n and body[i + 1] == "*":
                in_comment = True
                comment_line = line
                i += 2
                continue
            if ch == "/" and i + 1 < n and body[i + 1] == "/":
                i += 2
                while i < n and body[i] != "\r" and body[i] != "\n":
                    i += 1
                continue
            if ch == '"':
                in_string = True
                string_line = line
                string_buf = ['"']
                i += 1
                continue
            # word
            m = _SLOW_WORD_RE.match(body, i)
            if m:
                word = m.group(0)
                i = m.end()
                _lex_word_diagnostics(word, line, errors)
                if pending_line is None:
                    pending_line = line
                pending.append(word)

        # element boundary (a line end)
        if in_comment:
            line += 1
        elif in_string:
            string_buf.append("\n")
            line += 1
        else:
            if pending:
                yield pending_line, " ".join(pending)
                pending = []
                pending_line = None
            line += 1

    if in_comment:
        if pending:
            yield pending_line, " ".join(pending)
        errors.append(f"Line {comment_line}: comment not closed")
        return
    if in_string:
        if pending:
            yield pending_line, " ".join(pending)
        errors.append(f"Line {string_line}: quoted string not closed")
        return
    if pending:
        yield pending_line, " ".join(pending)


def build_section_tree(path: Path, progress: Optional[A2LProgress] = None) -> tuple[list[dict], list[str]]:
    """Public facade: build the section tree and return ``(sections, errors)``
    where ``errors`` is a plain list capped at 101 entries (E3A-19)."""
    errors = _CappedErrors()
    sections = _build_section_tree_into(path, progress, errors)
    return sections, errors.as_list()


def _build_section_tree_into(
    path: Path, progress: Optional[A2LProgress], errors: _CappedErrors
) -> list[dict]:
    """The section-tree builder of ``build_section_tree``, writing its errors
    into the ``_CappedErrors`` it is given."""
    sections: list[dict] = []
    stack: list[dict] = []
    pending_begin_line: Optional[int] = None
    pending_end_line: Optional[int] = None
    pending_include_line: Optional[int] = None
    line_count = 0

    try:
        with path.open("rb") as probe:
            head = probe.read(3)
    except FileNotFoundError:
        errors.append("File not found.")
        logger.warning("A2L section parse failed: path=%s reason=file_not_found", path)
        return sections
    except OSError:
        logger.exception("A2L section parse failed: path=%s reason=os_error", path)
        raise

    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        errors.reset("File is UTF-16 encoded; save it as UTF-8 and load it again.")
        logger.info("A2L section tree refused: path=%s reason=utf_16_bom", path)
        return sections

    utf8_bom = head[:3] == b"\xef\xbb\xbf"

    def _add_own_word(word: str, lnum: int) -> None:
        if not stack:
            return
        top = stack[-1]
        if top["meta_line"] == lnum:
            top["meta"] = (top["meta"] + " " + word) if top["meta"] else word
        elif (
            top["line_numbers"]
            and top["line_numbers"][-1] == lnum
            and top["lines"][-1] != ""
        ):
            top["lines"][-1] = top["lines"][-1] + " " + word
        else:
            top["lines"].append(word)
            top["line_numbers"].append(lnum)

    def _process_text(lnum: int, text: str) -> bool:
        nonlocal pending_begin_line, pending_end_line, pending_include_line
        structural = (
            pending_begin_line is not None
            or pending_end_line is not None
            or pending_include_line is not None
            or "/" in text
        )
        if not structural:
            if stack:
                stack[-1]["lines"].append(text)
                stack[-1]["line_numbers"].append(lnum)
            return True
        for word in _line_words(text):
            if pending_begin_line is not None:
                if len(stack) >= _MAX_NESTING:
                    errors.reset(f"Line {lnum}: sections nested deeper than 32")
                    return False
                entry = {
                    "name": word,
                    "meta": "",
                    "meta_line": lnum,
                    "start_line": pending_begin_line,
                    "end_line": None,
                    "lines": [],
                    "line_numbers": [],
                    "children": [],
                }
                if stack:
                    stack[-1]["lines"].append("")
                    stack[-1]["line_numbers"].append(pending_begin_line)
                    stack[-1]["children"].append(entry)
                else:
                    sections.append(entry)
                stack.append(entry)
                pending_begin_line = None
                continue
            if pending_end_line is not None:
                if stack:
                    top = stack[-1]
                    if top["name"] != word:
                        errors.append(
                            f"Line {lnum}: /end {_echo_word(word)} does not close "
                            f"/begin {_echo_word(top['name'])}"
                        )
                    top["end_line"] = lnum
                    stack.pop()
                else:
                    errors.append(f"Line {lnum}: /end without /begin")
                pending_end_line = None
                continue
            if pending_include_line is not None:
                errors.append(
                    f"Line {pending_include_line}: /include {_echo_word(_unquote(word))} is not read"
                )
                pending_include_line = None
                continue
            low = word.lower()
            if low == "/begin":
                pending_begin_line = lnum
                continue
            if low == "/end":
                pending_end_line = lnum
                continue
            if low == "/include":
                _add_own_word(word, lnum)
                pending_include_line = lnum
                continue
            _add_own_word(word, lnum)
        return True

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            total = os.fstat(handle.fileno()).st_size if progress is not None else 0

            def _elements() -> Iterator[str]:
                nonlocal line_count
                for index, element in enumerate(handle, 1):
                    line_count += 1
                    if progress is not None and line_count % _PROGRESS_LINES == 0:
                        progress(handle.buffer.tell(), total)
                    if index == 1 and utf8_bom and element.startswith("\ufeff"):
                        element = element[1:]
                    yield element

            for lnum, text in _lex_a2l_lines(_elements(), errors):
                if not _process_text(lnum, text):
                    return []
            if progress is not None:
                progress(total, total)
    except OSError:
        logger.exception("A2L section parse failed: path=%s reason=os_error", path)
        raise

    # A NUL refusal resets the errors to this one text and gives no section.
    if errors.as_list() == [_UTF8_NUL_REFUSAL]:
        return []

    # A trailing /begin, /end or /include with no following word is ordinary.
    if pending_begin_line is not None:
        _add_own_word("/begin", pending_begin_line)
    if pending_end_line is not None:
        _add_own_word("/end", pending_end_line)
    pending_include_line = None

    if stack:
        errors.append("Unclosed /begin sections detected.")

    _apply_named_kind_meta(sections)
    logger.info(
        "A2L section tree built: path=%s lines=%d root_sections=%d errors=%d",
        path,
        line_count,
        len(sections),
        len(errors.as_list()),
    )
    return sections


def _apply_named_kind_meta(sections: list[dict]) -> None:
    """Move a named kind's name (and long identifier) from a later line into
    ``meta`` (DE-3 revised, R-A2L-READ.54, E3A-01)."""
    for node in sections:
        if node.get("name") in _NAMED_KINDS and not (node.get("meta") or ""):
            lines = node.get("lines")
            line_numbers = node.get("line_numbers")
            if lines:
                i = 0
                while i < len(lines) and lines[i] == "":
                    i += 1
                if i < len(lines):
                    meta = lines.pop(i)
                    meta_line = line_numbers.pop(i) if line_numbers and i < len(line_numbers) else node.get("start_line")
                    if _is_single_word(meta):
                        j = i
                        while j < len(lines) and lines[j] == "":
                            j += 1
                        if j < len(lines):
                            second_words = list(_line_words(lines[j]))
                            if second_words and second_words[0].startswith('"'):
                                meta = meta + " " + lines.pop(j)
                                if line_numbers and j < len(line_numbers):
                                    line_numbers.pop(j)
                    node["meta"] = meta
                    node["meta_line"] = meta_line
        _apply_named_kind_meta(node.get("children") or [])


def parse_begin_meta(meta: str) -> tuple[str, Optional[str]]:
    """Parse /begin SECTION name long_identifier from meta string (quoted OK)."""
    meta = (meta or "").strip()
    if not meta:
        return "UNKNOWN", None
    name, rest = _parse_first_field(meta)
    description: Optional[str] = None
    if rest:
        description, _ = _parse_first_field(rest.strip())
        if description == "":
            description = None
    return name or "UNKNOWN", description


def _parse_first_field(meta: str) -> tuple[str, str]:
    """Return first identifier or quoted string, and remainder.

    A backslash and the character after it form one pair, so ``\"`` does not
    close and ``\\\\"`` does; an unquoted field ends at an ASCII blank, a line
    end or a ``"`` (R-A2L-001.3.2, R-A2L-READ.2).
    """
    meta = (meta or "").strip(" \t\x0b\x0c\r\n")
    if not meta:
        return "", ""
    if meta[0] == '"':
        j = _find_string_end(meta, 1)
        if j < 0:
            return meta[1:], ""
        return meta[1:j], meta[j + 1 :].lstrip(" \t\x0b\x0c\r\n")
    i = 0
    n = len(meta)
    while i < n and meta[i] not in _BLANKS and meta[i] not in "\r\n\"":
        i += 1
    return meta[:i], meta[i:].lstrip(" \t\x0b\x0c\r\n")


def _find_first_non_empty_line(lines: list[str]) -> Optional[str]:
    for line in lines:
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _to_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_byte_order(token: Optional[str]) -> Optional[str]:
    raw = (token or "").strip().upper()
    if raw in {"MSB_FIRST", "BIG_ENDIAN"}:
        return "big"
    if raw in {"MSB_LAST", "LITTLE_ENDIAN"}:
        return "little"
    return None


def _byte_order_from_section_lines(lines: list[str]) -> Optional[str]:
    for line in lines:
        parts = _split_line_respecting_quotes(line.strip())
        if len(parts) >= 2 and parts[0] == "BYTE_ORDER":
            return _normalize_byte_order(parts[1])
    return None


def _split_line_respecting_quotes(line: str) -> list[str]:
    """Split one line into words honouring quoted spans (ASCII blanks only;
    a backslash pair inside a quoted word; a ``"`` ends an unquoted word)."""
    line = (line or "").strip(" \t\x0b\x0c\r\n")
    if not line:
        return []
    tokens: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        while i < n and (line[i] in _BLANKS or line[i] in "\r\n"):
            i += 1
        if i >= n:
            break
        if line[i] == '"':
            j = _find_string_end(line, i + 1)
            if j < 0:
                tokens.append(line[i + 1 :])
                break
            tokens.append(line[i + 1 : j])
            i = j + 1
            continue
        j = i
        while j < n and line[j] not in _BLANKS and line[j] not in "\r\n\"":
            j += 1
        tokens.append(line[i:j])
        i = j
    return tokens


#: Sentinel joining body lines before comment-stripping so a ``//`` line comment
#: can be truncated at the next line boundary (not the whole flattened body).
_A2L_LINE_SENTINEL = "\n"


def _strip_a2l_comments(text: str) -> str:
    """
    Summary:
        Remove A2L block (``/* … */``) and line (``//``) comments from a
        (possibly multi-line) body while preserving the bytes of any quoted
        string verbatim. A single linear pass with a quote-state machine: ``/``
        and ``*`` inside ``"…"`` are literal; a ``//`` truncates only to the
        next newline sentinel (never the whole body); an unterminated ``/*`` or
        ``"`` consumes to end without raising.

    Args:
        text (str): Raw A2L text, typically several body lines joined by
            ``_A2L_LINE_SENTINEL``.

    Returns:
        str: ``text`` with comments removed and every quoted span byte-identical.

    Raises:
        None: Malformed/unterminated comment or quote syntax degrades gracefully.

    Data Flow:
        - Scan char-by-char, tracking whether the cursor is inside a quoted span.
        - Outside quotes: drop ``/* … */`` (spanning newlines) and ``// … <\n>``.
        - Inside quotes: copy literally; a ``"`` closes only when not backslash
          escaped (same convention as ``_split_line_respecting_quotes``).

    Dependencies:
        Uses:
            - ``_A2L_LINE_SENTINEL``
        Used by:
            - ``_flatten_body_tokens``

    Example:
        >>> _strip_a2l_comments('CURVE /* c */ 0x1  // tail\\nRL')
        'CURVE  0x1  \\nRL'
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == '"':
                k = i - 1
                backslashes = 0
                while k >= 0 and text[k] == "\\":
                    backslashes += 1
                    k -= 1
                if backslashes % 2 == 0:
                    in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            if not out or out[-1] not in " \t\x0b\x0c\r\n":
                out.append(" ")
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = i + 2 if i + 1 < n else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            if not out or out[-1] not in " \t\x0b\x0c\r\n":
                out.append(" ")
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _flatten_body_tokens(lines: list[str]) -> list[str]:
    """
    Summary:
        Join a section's body lines, strip comments across the joined text, and
        tokenise the result honouring quoted spans — the multi-line analogue of
        ``_split_line_respecting_quotes``. Join-first so a block comment that
        spans several lines is removed as one unit.

    Args:
        lines (list[str]): The section body lines (no ``/begin``/``/end``).

    Returns:
        list[str]: Whitespace/newline-separated tokens with comments removed and
        quoted strings preserved as single tokens.

    Raises:
        None.

    Data Flow:
        - ``\\n``-join → ``_strip_a2l_comments`` → ``_split_line_respecting_quotes``.

    Dependencies:
        Uses:
            - ``_strip_a2l_comments`` ; ``_split_line_respecting_quotes`` ;
              ``_A2L_LINE_SENTINEL``
        Used by:
            - ``assemble_characteristic_header`` ; AXIS_DESCR capture in
              ``extract_a2l_tags``

    Example:
        >>> _flatten_body_tokens(['CURVE /* c */', '0x1 RL'])
        ['CURVE', '0x1', 'RL']
    """
    throwaway = _CappedErrors()
    tokens: list[str] = []
    for _lnum, text in _lex_a2l_lines(lines, throwaway):
        for word in _line_words(text):
            tokens.append(_unquote(word))
    return tokens


def sizeof_from_deposit(deposit: str) -> Optional[int]:
    """Infer element size from common record layout naming (e.g. __UBYTE_Z)."""
    u = deposit.upper()
    for marker, size in (
        ("__FLOAT64_IEEE_Z", 8),
        ("__FLOAT32_IEEE_Z", 4),
        ("__FLOAT16_IEEE_Z", 2),
        ("__UBYTE_Z", 1),
        ("__SBYTE_Z", 1),
        ("__UWORD_Z", 2),
        ("__SWORD_Z", 2),
        ("__ULONG_Z", 4),
        ("__SLONG_Z", 4),
    ):
        if marker in u:
            return size
    if u in DATATYPE_SIZES:
        return DATATYPE_SIZES[u]
    return None


def parse_measurement_header(line: str) -> Optional[dict]:
    """Parse a MEASUREMENT header's positional words (by position, up to the
    first keyword, at most 6)."""
    parts = _split_line_respecting_quotes(line)
    header: list[str] = []
    for word in parts:
        if word in _TAG_KEYWORD_ARITY:
            break
        header.append(word)
        if len(header) == 6:
            break
    if not header:
        return None
    return {
        "datatype": header[0] if len(header) > 0 else None,
        "conversion": header[1] if len(header) > 1 else None,
        "resolution": header[2] if len(header) > 2 else None,
        "accuracy": header[3] if len(header) > 3 else None,
        "lower_limit": header[4] if len(header) > 4 else None,
        "upper_limit": header[5] if len(header) > 5 else None,
        "address_inline": None,
    }


def _characteristic_from_tokens(tokens: list[str]) -> Optional[dict]:
    """
    Summary:
        Build a CHARACTERISTIC mandatory-header dict from a flat token list by
        anchoring on the first ``CHARACTERISTIC_KINDS`` token (the ``Type``) and
        reading the 7 positional mandatory params from there:
        ``Type Address Deposit MaxDiff Conversion LowerLimit UpperLimit``. Fails
        closed (returns ``None``) when no kind token is present or fewer than 7
        tokens follow it — never raises ``IndexError``. A header whose ``Type``
        is a tool-specific kind outside ``CHARACTERISTIC_KINDS`` (B6 — the
        vendor layouts with ``DIRECT``/``NO_AXIS_PTS_*``) is salvaged: the raw
        kind is kept and the same 7 params are read from the shaped Type slot,
        so the label keeps its live address instead of degrading to ``None``.

    Args:
        tokens (list[str]): Comment-stripped, quote-respecting header tokens
            (single line or flattened multi-line body).

    Returns:
        Optional[dict]: The shipped header dict (``char_type``,
        ``address_inline``, ``deposit``, ``max_diff``, ``conversion``,
        ``lower_limit``, ``upper_limit``, ``datatype``), or ``None``.

    Raises:
        None.

    Data Flow:
        - Find the first token in ``CHARACTERISTIC_KINDS`` (the anchor).
        - No known kind → fall back to ``_extended_kind_anchor`` (B6 salvage).
        - Slice 7 params from the anchor; ``None`` if the slice is short.
        - Parse the address via ``int(x, 0)``; ``ValueError`` → ``None`` address.

    Dependencies:
        Uses:
            - ``CHARACTERISTIC_KINDS`` ; ``MEASUREMENT_BODY_KEYWORDS`` ;
              ``_extended_kind_anchor``
        Used by:
            - ``parse_characteristic_header`` ; ``assemble_characteristic_header``

    Note:
        Anchoring on the first kind token treats a bare unquoted kind-word used
        as a name/long-identifier as the Type — a documented non-goal (the real
        ASAM corpus always quotes or dots identifiers, so this cannot occur
        there; a synthetic bare-kind-word-before-Type degrades to
        ``address=None``, never a crash).

    Example:
        >>> _characteristic_from_tokens(["desc", "VALUE", "0x10", "RL", "0",
        ...                              "CM", "0", "255"])["char_type"]
        'VALUE'
    """
    anchor: Optional[int] = None
    for idx, token in enumerate(tokens):
        if token in CHARACTERISTIC_KINDS:
            anchor = idx
            break
    if anchor is None:
        # B6: an extended tool-specific kind is not in CHARACTERISTIC_KINDS,
        # but a header whose Type slot is followed by a parseable address is
        # still ASAP2-shaped — salvage it so the label survives (raw kind,
        # live address) instead of losing the whole header to address=None.
        anchor = _extended_kind_anchor(tokens)
    if anchor is None:
        return None
    params = tokens[anchor : anchor + 7]
    if len(params) < 7:
        return None
    address_inline: Optional[int] = _number_word(params[1])
    return {
        "char_type": params[0],
        "address_inline": address_inline,
        "deposit": params[2],
        "max_diff": params[3],
        "conversion": params[4],
        "lower_limit": params[5],
        "upper_limit": params[6],
        "datatype": None,
    }


def _extended_kind_anchor(tokens: list[str]) -> Optional[int]:
    """Locate a shaped ``Type`` slot carrying an unknown (extended) kind.

    B6: some tools emit a CHARACTERISTIC whose ``Type`` is outside
    ``CHARACTERISTIC_KINDS`` (e.g. the vendor kind paired with the
    ``FNC_VALUES … DIRECT / NO_AXIS_PTS_*`` layouts). The first pass then finds
    no anchor and the whole header — address included — used to be discarded.
    A token is a salvage anchor only when it can plausibly BE a Type: not a
    known kind, not a body keyword, not itself a number, and immediately
    followed by an ``int(x, 0)``-parseable address with ≥7 params remaining.
    Everything else (keyword bodies like ``ECU_ADDRESS 0x… LENGTH …``) still
    yields ``None``.
    """
    for idx in range(0, len(tokens) - 6):
        candidate = tokens[idx]
        if candidate in CHARACTERISTIC_KINDS or candidate in MEASUREMENT_BODY_KEYWORDS:
            continue
        if _number_word(candidate) is not None:
            continue  # an address/number token, never a Type identifier
        if _number_word(tokens[idx + 1]) is None:
            continue  # no parseable address right after → not a header Type slot
        return idx
    return None


def parse_characteristic_header(line: str) -> Optional[dict]:
    """Parse a single-line CHARACTERISTIC mandatory header (back-compat shim)."""
    return _characteristic_from_tokens(_split_line_respecting_quotes(line))


def assemble_characteristic_header(lines: list[str]) -> Optional[dict]:
    """
    Summary:
        Assemble a CHARACTERISTIC mandatory header whose params may span multiple
        body lines (the real ASAM convention). Flattens the body with comment
        stripping, then anchors on the first ``CHARACTERISTIC_KINDS`` token. The
        single-line case is a strict subset (one line flattens to its own
        tokens), so this never regresses ``parse_characteristic_header``.

    Args:
        lines (list[str]): The CHARACTERISTIC block's body lines (no
            ``/begin``/``/end``; nested ``AXIS_DESCR`` etc. already split out by
            ``build_section_tree``).

    Returns:
        Optional[dict]: Same shape as ``parse_characteristic_header`` (shipped
        keys ``char_type``/``address_inline``/``deposit``/``max_diff``/
        ``conversion``/``lower_limit``/``upper_limit``/``datatype``), or ``None``
        when no kind token / no shaped extended-kind slot / fewer than 7 params.

    Raises:
        None.

    Data Flow:
        - ``_flatten_body_tokens(lines)`` → ``_characteristic_from_tokens``.

    Dependencies:
        Uses:
            - ``_flatten_body_tokens`` ; ``_characteristic_from_tokens``
        Used by:
            - CHARACTERISTIC branch of ``extract_a2l_tags``

    Example:
        >>> assemble_characteristic_header(['"desc"', 'CURVE 0x810300',
        ...     'RL.X 0 CM 0 255'])["address_inline"]
        8455936
    """
    return _characteristic_from_tokens(_flatten_body_tokens(lines))


def _parse_link_map_line(line: str) -> Optional[dict]:
    stripped = line.strip()
    if not stripped.startswith("LINK_MAP"):
        return None
    tokens = _split_line_respecting_quotes(stripped)
    if len(tokens) < 2:
        return {"name": None, "values": []}
    return {"name": tokens[1], "values": tokens[2:]}


def collect_link_maps(section: dict) -> list[dict]:
    """Shallow-scan IF_DATA subtrees for LINK_MAP lines (Vector CANape)."""
    found: list[dict] = []

    def walk(sec: dict) -> None:
        for child in sec.get("children") or []:
            cname = child.get("name", "")
            if cname == "IF_DATA":
                for raw in child.get("lines", []):
                    parsed = _parse_link_map_line(raw)
                    if parsed:
                        found.append(parsed)
            walk(child)

    walk(section)
    return found


def _collect_sections_by_name(sections: list[dict], target_name: str) -> list[dict]:
    found: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            if node.get("name") == target_name:
                found.append(node)
            walk(node.get("children") or [])

    walk(sections)
    return found


def extract_record_layouts(sections: list[dict]) -> dict[str, dict]:
    """Extract RECORD_LAYOUT sections keyed by layout name."""
    out: dict[str, dict] = {}
    for section in _collect_sections_by_name(sections, "RECORD_LAYOUT"):
        layout_name, _ = parse_begin_meta(section.get("meta", "") or "")
        lines = section.get("lines") or []
        first_line = _find_first_non_empty_line(lines)
        tokens = _split_line_respecting_quotes(first_line or "")
        item = {
            "name": layout_name,
            "tokens": tokens,
            "lines": lines,
            "byte_order": _byte_order_from_section_lines(lines),
        }
        out[layout_name] = item
    return out


def _parse_compu_conversion_tokens(tokens: list[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Summary:
        Parse ASAP2 ``COMPU_METHOD`` conversion line tokens into conversion type, display format, and physical unit.

    Args:
        tokens (list[str]): Token list from ``_split_line_respecting_quotes`` for one non-empty line.

    Returns:
        tuple[Optional[str], Optional[str], Optional[str]]: ``(conversion_type, format, unit)`` when recognized.

    Raises:
        None

    Data Flow:
        - Detect a leading conversion keyword token.
        - Treat the next quoted token as display format when present.
        - Treat the following quoted token as physical unit when present.

    Dependencies:
        Uses:
        - ``COMPU_CONVERSION_KEYWORDS``
        Used by:
        - ``extract_compu_methods``
    """
    if not tokens:
        return None, None, None
    head = tokens[0]
    if head not in COMPU_CONVERSION_KEYWORDS:
        return None, None, None
    conversion_type = head
    fmt = tokens[1] if len(tokens) > 1 else None
    unit = tokens[2] if len(tokens) > 2 else None
    return conversion_type, fmt, unit


def _parse_compu_method_conversion_from_body(lines: list[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Summary:
        Scan ``COMPU_METHOD`` body lines for the primary conversion declaration.

    Args:
        lines (list[str]): Raw lines inside a ``COMPU_METHOD`` section.

    Returns:
        tuple[Optional[str], Optional[str], Optional[str]]: ``(conversion_type, format, unit)`` when found.

    Raises:
        None

    Data Flow:
        - Skip blank lines.
        - Tokenize each line with quote-aware splitting.
        - Return the first line that begins with a known conversion keyword.

    Dependencies:
        Uses:
        - ``_split_line_respecting_quotes``
        - ``_parse_compu_conversion_tokens``
        Used by:
        - ``extract_compu_methods``
    """
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        tokens = _split_line_respecting_quotes(stripped)
        parsed = _parse_compu_conversion_tokens(tokens)
        if parsed[0] is not None:
            return parsed
    return None, None, None


def _parse_compu_method_conversion_from_meta(meta_tokens: list[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Summary:
        Best-effort parse of conversion type, format, and unit from ``/begin COMPU_METHOD`` meta tokens.

    Args:
        meta_tokens (list[str]): Token list from ``_split_line_respecting_quotes`` applied to meta text.

    Returns:
        tuple[Optional[str], Optional[str], Optional[str]]: ``(conversion_type, format, unit)`` when a conversion keyword is found.

    Raises:
        None

    Data Flow:
        - Locate a conversion keyword token inside meta.
        - If preceded by a quoted token, treat it as format.
        - If followed by quoted tokens, treat them as format/unit depending on position.

    Dependencies:
        Uses:
        - ``COMPU_CONVERSION_KEYWORDS``
        Used by:
        - ``extract_compu_methods``
    """
    if not meta_tokens:
        return None, None, None
    for index, token in enumerate(meta_tokens):
        if token not in COMPU_CONVERSION_KEYWORDS:
            continue
        conversion_type = token
        fmt = meta_tokens[index - 1] if index >= 1 else None
        unit = None
        if index + 1 < len(meta_tokens):
            candidate = meta_tokens[index + 1]
            if candidate not in COMPU_CONVERSION_KEYWORDS:
                unit = candidate
        return conversion_type, fmt, unit
    return None, None, None


def extract_compu_methods(sections: list[dict]) -> dict[str, dict]:
    """Extract COMPU_METHOD definitions keyed by method name."""
    out: dict[str, dict] = {}
    for section in _collect_sections_by_name(sections, "COMPU_METHOD"):
        meta = section.get("meta", "") or ""
        meta_tokens = _split_line_respecting_quotes(meta)
        method_name = meta_tokens[0] if meta_tokens else "UNKNOWN"
        lines = section.get("lines") or []
        body_conversion = _parse_compu_method_conversion_from_body(lines)
        meta_conversion = _parse_compu_method_conversion_from_meta(meta_tokens)
        conversion_type = body_conversion[0] or meta_conversion[0]
        fmt = body_conversion[1] or meta_conversion[1]
        unit = body_conversion[2] or meta_conversion[2]
        # E9 (batch-96): the COMPU_METHOD's long identifier — the quoted
        # description on the /begin line — rides along for the parameter
        # description. Purely additive: every pre-E9 key keeps its shape.
        _parsed_name, long_identifier = parse_begin_meta(meta)
        method = {
            "name": method_name,
            "long_identifier": long_identifier,
            "conversion_type": conversion_type,
            "format": fmt,
            "unit": unit,
            "coeffs_linear": None,
            "coeffs": None,
            "compu_tab_ref": None,
            "formula": None,
            "lines": lines,
        }
        for line in lines:
            parts = _split_line_respecting_quotes(line.strip())
            if not parts:
                continue
            head = parts[0]
            if head in COMPU_CONVERSION_KEYWORDS:
                line_conv, line_fmt, line_unit = _parse_compu_conversion_tokens(parts)
                if line_conv is not None:
                    method["conversion_type"] = line_conv
                    if line_fmt is not None:
                        method["format"] = line_fmt
                    if line_unit is not None:
                        method["unit"] = line_unit
                continue
            if head == "COEFFS_LINEAR" and len(parts) >= 3:
                method["coeffs_linear"] = [_to_float(parts[1]), _to_float(parts[2])]
            elif head == "COEFFS" and len(parts) >= 7:
                method["coeffs"] = [_to_float(parts[i]) for i in range(1, 7)]
            elif head == "COMPU_TAB_REF" and len(parts) >= 2:
                method["compu_tab_ref"] = parts[1]
            elif head == "FORM" and len(parts) >= 2:
                method["formula"] = parts[1]
        out[method_name] = method
    return out


def extract_compu_tables(sections: list[dict]) -> dict[str, dict]:
    """Extract COMPU_TAB/COMPU_VTAB sections keyed by table name."""
    out: dict[str, dict] = {}
    for section_name in ("COMPU_TAB", "COMPU_VTAB"):
        for section in _collect_sections_by_name(sections, section_name):
            table_name, _ = parse_begin_meta(section.get("meta", "") or "")
            lines = section.get("lines") or []
            entries: list[tuple[float, Any]] = []
            first_line = _find_first_non_empty_line(lines)
            table_kind = None
            if first_line:
                first_tokens = _split_line_respecting_quotes(first_line)
                if first_tokens:
                    table_kind = first_tokens[0]
            for line in lines:
                parts = _split_line_respecting_quotes(line.strip())
                if len(parts) < 2:
                    continue
                x = _to_float(parts[0])
                if x is None:
                    continue
                y_num = _to_float(parts[1])
                entries.append((x, y_num if y_num is not None else parts[1]))
            out[table_name] = {
                "name": table_name,
                "section": section_name,
                "kind": table_kind,
                "entries": sorted(entries, key=lambda item: item[0]),
                "lines": lines,
            }
    return out


PROGRAM_TYPE_WORDS = frozenset(
    {
        "CALIBRATION_VARIABLES",
        "CODE",
        "DATA",
        "EXCLUDE_FROM_FLASH",
        "OFFLINE_DATA",
        "RESERVED",
        "SERAM",
        "VARIABLES",
    }
)

MEMORY_TYPE_WORDS = frozenset(
    {"EEPROM", "EPROM", "FLASH", "NOT_IN_ECU", "RAM", "REGISTER", "ROM"}
)


def _a2l_number(word: str) -> Optional[int]:
    """Parse an ASCII Number word, or ``None`` when the word is not one.

    The value when ``word`` fully matches the ASCII pattern
    ``[+-]?(0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10})``: decimal digits read in base
    10 (so ``0400`` is 400) and hex digits in base 16, with the sign. No other
    word is a Number: not ``0o``/``0b``, not a word with ``_``, not a
    non-ASCII digit, not a longer digit run. Never called for a quoted word.
    """
    if not word:
        return None
    text = word
    sign = 1
    if text[0] in "+-":
        if text[0] == "-":
            sign = -1
        text = text[1:]
    if not text:
        return None
    if text[:2] in ("0x", "0X"):
        digits = text[2:]
        if not 1 <= len(digits) <= 8:
            return None
        if any(ch not in "0123456789abcdefABCDEF" for ch in digits):
            return None
        return sign * int(digits, 16)
    if not 1 <= len(text) <= 10:
        return None
    if not all("0" <= ch <= "9" for ch in text):
        return None
    return sign * int(text, 10)


def _memory_segment_record_words(
    sec: dict,
) -> tuple[list[tuple[str, int, bool]], list[str]]:
    """Collect the record words of a MEMORY_SEGMENT block from its canonical
    texts (``meta`` then each own ``line``), quoted words without their quotes
    and flagged."""
    texts: list[str] = [sec.get("meta") or "", *(sec.get("lines") or [])]
    words: list[tuple[str, int, bool]] = []
    for text_index, text in enumerate(texts):
        for word in _line_words(text):
            if word.startswith('"'):
                words.append((_unquote(word), text_index, True))
            else:
                words.append((word, text_index, False))
    return words, list(texts)


def extract_memory_segments(sections: list[dict]) -> list[dict]:
    """Parse MEMORY_SEGMENT blocks into name, usage, kind, base, size, offset.

    Anchored rule (batch-101 Inc 11): the record words come from
    :func:`_memory_segment_record_words` (the ``/begin`` line's words after
    ``/begin MEMORY_SEGMENT``, then each own line). The name is the first
    record word; the address word is the first unquoted word after the name
    that starts with an ASCII digit or sign; base and size are that word and
    the word after it as ASCII Numbers, kept only when base ≥ 0, size > 0 and
    base + size ≤ 2^32. Usage and kind are the last program-type / memory-type
    word before the address word. No address word or a failed check leaves
    every numeric field ``None`` with no further scan.
    """
    out: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for sec in nodes:
            if sec.get("name") != "MEMORY_SEGMENT":
                walk(sec.get("children") or [])
                continue
            entry: dict = {
                "block_name": None,
                "raw_first_line": "",
                "usage": None,
                "kind": None,
                "base": None,
                "size": None,
                "offset": None,
            }
            words, texts = _memory_segment_record_words(sec)
            if words:
                entry["block_name"] = words[0][0] or None
                k = None
                for idx in range(1, len(words)):
                    text, _, quoted = words[idx]
                    if not quoted and text and text[0] in "0123456789+-":
                        k = idx
                        break
                if k is not None:
                    base = _a2l_number(words[k][0])
                    size = None
                    if k + 1 < len(words) and not words[k + 1][2]:
                        size = _a2l_number(words[k + 1][0])
                    if (
                        base is not None
                        and size is not None
                        and base >= 0
                        and size > 0
                        and base + size <= 2**32
                    ):
                        entry["base"] = base
                        entry["size"] = size
                        entry["raw_first_line"] = texts[words[k][1]].strip()
                        if k + 2 < len(words) and not words[k + 2][2]:
                            entry["offset"] = _a2l_number(words[k + 2][0])
                        usage = None
                        kind = None
                        for idx in range(1, k):
                            text = words[idx][0]
                            if text in PROGRAM_TYPE_WORDS:
                                usage = text
                            if text in MEMORY_TYPE_WORDS:
                                kind = text
                        entry["usage"] = usage
                        entry["kind"] = kind
            out.append(entry)
            walk(sec.get("children") or [])

    walk(sections)
    return out


def classify_address(address: Optional[int], segments: list[dict]) -> str:
    """Classify address as flash, ram, or unknown using MEMORY_SEGMENT ranges."""
    if address is None or not segments:
        return "unknown"
    for seg in segments:
        base = seg.get("base")
        size = seg.get("size")
        kind = (seg.get("kind") or "").upper()
        usage = (seg.get("usage") or "").upper()
        if base is None or size is None or size < 0:
            continue
        if not (base <= address < base + size):
            continue
        if kind == "RAM" or usage == "VARIABLE":
            return "ram"
        if kind in {"FLASH", "ROM"} or usage == "CODE":
            return "flash"
        if usage == "DATA" and kind == "ROM":
            return "flash"
        if usage == "DATA" and kind == "RAM":
            return "ram"
    return "unknown"


def _apply_conversion_source(tag: dict, conversion_token: Optional[str]) -> None:
    if not conversion_token or conversion_token == "NO_COMPU_METHOD":
        return
    tag["source"] = "formula"


def _infer_length_measurement(lines: list[str], header: Optional[dict]) -> Optional[int]:
    """Infer a MEASUREMENT's length from its ``_tag_keyword_lines`` texts."""
    data_size_or_length: Optional[int] = None
    array_size: Optional[int] = None
    matrix = 1
    for text in lines:
        parts = text.split(" ")
        if parts[0] in ("DATA_SIZE", "LENGTH") and len(parts) == 2:
            value = _number_word(parts[1])
            if value is not None:
                data_size_or_length = value
        if parts[0] == "ARRAY_SIZE" and len(parts) == 2:
            value = _number_word(parts[1])
            if value is not None:
                array_size = value
        if parts[0] == "MATRIX_DIM":
            prod = 1
            ok = _MATRIX_DIM_MIN <= len(parts) - 1 <= _MATRIX_DIM_MAX
            if ok:
                for arg in parts[1:]:
                    value = _number_word(arg)
                    if value is None:
                        ok = False
                        break
                    prod *= value
            if ok:
                matrix = prod
    if data_size_or_length is not None:
        return data_size_or_length
    dt = (header or {}).get("datatype")
    if dt and dt in DATATYPE_SIZES:
        if array_size is not None:
            return DATATYPE_SIZES[dt] * array_size
        return DATATYPE_SIZES[dt] * matrix
    return None


def _infer_length_characteristic(
    lines: list[str],
    header: Optional[dict],
    record_layouts_by_name: Optional[dict[str, dict]] = None,
) -> Optional[int]:
    """Infer a CHARACTERISTIC's length from its ``_tag_keyword_lines`` texts."""
    explicit: Optional[int] = None
    matrix: Optional[int] = None
    number: Optional[int] = None
    for text in lines:
        parts = text.split(" ")
        if parts[0] == "LENGTH" and len(parts) == 2:
            value = _number_word(parts[1])
            if value is not None:
                explicit = value
        if parts[0] == "MATRIX_DIM":
            prod = 1
            ok = _MATRIX_DIM_MIN <= len(parts) - 1 <= _MATRIX_DIM_MAX
            if ok:
                for arg in parts[1:]:
                    value = _number_word(arg)
                    if value is None:
                        ok = False
                        break
                    prod *= value
            if ok:
                matrix = prod
        if parts[0] == "NUMBER" and len(parts) == 2:
            value = _number_word(parts[1])
            if value is not None:
                number = value
    if explicit is not None:
        return explicit
    h = header or {}
    deposit = str(h.get("deposit") or "")
    char_type = h.get("char_type")
    el = sizeof_from_deposit(deposit)
    if el is None and char_type in ("VALUE", "VAL_BLK") and record_layouts_by_name:
        meta = _resolve_record_layout(deposit, record_layouts_by_name)
        if meta and meta.get("decode_type"):
            el = DATATYPE_SIZES.get(meta["decode_type"])
    if char_type == "ASCII":
        if number is not None:
            return number
        if matrix is not None:
            return matrix
        return None
    if el is None:
        return None
    if char_type == "VAL_BLK":
        if matrix is not None and matrix > 0:
            return el * matrix
        if number is not None:
            return el * number
        return None
    if matrix is not None and matrix > 0:
        return el * matrix
    return el


def _resolve_record_layout(layout_name: Optional[str], record_layouts_by_name: dict[str, dict]) -> Optional[dict]:
    """Resolve record layout into decode metadata."""
    if not layout_name:
        return None
    layout = record_layouts_by_name.get(layout_name)
    if not layout:
        return None
    tokens = layout.get("tokens") or []
    decode_token = None
    for token in tokens:
        if token in DATATYPE_SIZES:
            decode_token = token
            break
    if decode_token is None:
        hinted = sizeof_from_deposit(layout_name)
        if hinted:
            for dt, size in DATATYPE_SIZES.items():
                if size == hinted and dt in DATATYPE_STRUCT_CODES:
                    decode_token = dt
                    break
    if decode_token is None:
        return None
    # B6: token[1] of every ASAM RECORD_LAYOUT component line is the POSITION
    # INDEX, never a count — the first line's first number must not inflate
    # the decode unit (only the full multi-line span via
    # ``_record_layout_full_span`` may sum counts).
    element_count = 1
    byte_size = DATATYPE_SIZES.get(decode_token, 0) * max(1, element_count)
    return {
        "decode_type": decode_token,
        "element_count": max(1, element_count),
        "byte_size": byte_size if byte_size > 0 else None,
        "decode_endian": layout.get("byte_order"),
    }


def _inline_axis_counts(axis_meta: list[dict]) -> Optional[list[int]]:
    """
    Summary:
        Resolve the ordered inline axis point-counts for a CURVE/MAP, or ``None``
        when the axis set is empty, any axis is external, or any ``MaxAxisPoints``
        is not a positive decimal integer (the full-span-or-None entry gate).

    Args:
        axis_meta (list[dict]): The tag's ``axis_meta`` entries built at parse
            time; each carries ``header_tokens`` (token[0] = axis kind),
            ``max_axis_points`` (a decimal STRING), and an ``external`` flag.

    Returns:
        Optional[list[int]]: One positive int per axis in AXIS_DESCR order when
            every axis is inline (STD_AXIS/FIX_AXIS) and numerically sized; else
            ``None``.

    Raises:
        None: A non-numeric, leading-zero, or oversized ``max_axis_points`` is
            caught and yields ``None`` rather than propagating (collect-don't-abort).

    Data Flow:
        - Reject an empty axis list.
        - Per axis: read the kind from ``header_tokens[0]``, reject a kind outside
          ``_DERIVABLE_AXIS_KINDS`` and the ``external`` flag, then base-10
          ``int``-cast the string ``max_axis_points`` inside a try/except.
        - Return the ordered counts, or ``None`` on the first failure.

    Dependencies:
        Uses:
            - ``_DERIVABLE_AXIS_KINDS``
        Used by:
            - ``extract_a2l_tags`` post-axis-walk length pass

    Example:
        >>> _inline_axis_counts([{"header_tokens": ["STD_AXIS"], "max_axis_points": "8", "external": False}])
        [8]
    """
    if not axis_meta:
        return None
    counts: list[int] = []
    for axis in axis_meta:
        header_tokens = axis.get("header_tokens") or []
        if not header_tokens:
            return None
        if header_tokens[0] not in _DERIVABLE_AXIS_KINDS:
            return None
        if axis.get("external"):
            return None
        mp = axis.get("max_axis_points")
        if mp is None:
            return None
        try:
            count = int(str(mp).strip())
        except (ValueError, TypeError):
            return None
        if count <= 0:
            return None
        counts.append(count)
    return counts


def _positive_decimal_count(value: Any) -> Optional[int]:
    """Cast a ``max_axis_points`` token to a positive int, else ``None``."""
    try:
        count = int(str(value).strip())
    except (ValueError, TypeError):
        return None
    return count if count > 0 else None


def _axis_counts_resolving_external(axis_meta: list[dict], tags: list[dict]) -> Optional[list[int]]:
    """
    Summary:
        R5 extension of :func:`_inline_axis_counts`: resolve the ordered axis
        point-counts for a CURVE/MAP whose axis set MAY include external axes
        (COM_AXIS / RES_AXIS / CURVE_AXIS via ``AXIS_PTS_REF``). Inline axes
        count exactly as before; an external axis takes its count from the
        referenced AXIS_PTS record — in the operator's files a CHARACTERISTIC
        whose own ``axis_meta`` carries ``MaxAxisPoints`` — looked up BY NAME
        in the completed tag list.

    Args:
        axis_meta (list[dict]): The tag's ``axis_meta`` entries (same shape
            ``extract_a2l_tags`` builds: ``header_tokens``, ``max_axis_points``,
            ``external``).
        tags (list[dict]): The COMPLETED tag list of the parse payload — the
            referenced AXIS_PTS CHARACTERISTIC may be declared after the
            referencing CURVE/MAP, which is why this runs as a post-pass.

    Returns:
        Optional[list[int]]: One positive int per axis in AXIS_DESCR order when
        every inline axis is derivable AND every external axis's reference
        resolves to a tag with a positive numeric ``max_axis_points``;
        else ``None`` (full-span-or-None — never an invented count).

    Raises:
        None: A non-numeric/negative count, an absent ``AXIS_PTS_REF`` name,
            a dangling reference (no CHARACTERISTIC by that name), or a
            referenced tag without axis_meta all degrade to ``None``.

    Data Flow:
        - Reject an empty axis list.
        - Inline axis (no ``external`` flag): same contract as
          ``_inline_axis_counts`` — kind must be in ``_DERIVABLE_AXIS_KINDS``,
          count is the base-10 int of ``max_axis_points``.
        - External axis: locate ``AXIS_PTS_REF`` in ``header_tokens`` and take
          the NEXT token as the reference name; find the first tag with that
          name; read its FIRST ``axis_meta`` entry's ``max_axis_points``. The
          local AXIS_DESCR header value is deliberately NOT a fallback — ASAP2
          documents it as "will be overwritten by max number of axis points of
          AXIS_PTS", so using it could over-report the span.

    Dependencies:
        Uses:
            - ``_DERIVABLE_AXIS_KINDS`` / ``_positive_decimal_count``
        Used by:
            - ``extract_a2l_tags`` R5 external-axis post-pass

    Example:
        >>> meta = [{"header_tokens": ["COM_AXIS", "NO_INPUT", "NO_CM", "8", "0", "255", "AXIS_PTS_REF", "AX"], "max_axis_points": "8", "external": True}]
        >>> tags = [{"name": "AX", "axis_meta": [{"max_axis_points": "5"}]}]
        >>> _axis_counts_resolving_external(meta, tags)
        [5]
    """
    if not axis_meta:
        return None
    counts: list[int] = []
    for axis in axis_meta:
        header_tokens = axis.get("header_tokens") or []
        if not header_tokens:
            return None
        if not axis.get("external"):
            if header_tokens[0] not in _DERIVABLE_AXIS_KINDS:
                return None
            count = _positive_decimal_count(axis.get("max_axis_points"))
            if count is None:
                return None
            counts.append(count)
            continue
        try:
            ref_index = header_tokens.index("AXIS_PTS_REF")
        except ValueError:
            return None
        if ref_index + 1 >= len(header_tokens):
            return None
        ref_name = header_tokens[ref_index + 1]
        ref_tag = next((t for t in tags if t.get("name") == ref_name), None)
        if ref_tag is None:
            return None
        ref_meta = ref_tag.get("axis_meta") or []
        if not ref_meta:
            return None
        count = _positive_decimal_count(ref_meta[0].get("max_axis_points"))
        if count is None:
            return None
        counts.append(count)
    return counts


def align_up(o: int, a: int) -> int:
    """
    Summary:
        Round ``o`` up to the next multiple of ``a`` — the inter-component padding
        primitive for the alignment-aware span walk (batch-56).

    Args:
        o (int): The current running offset.
        a (int): The alignment; ``a <= 1`` means no padding (packed).

    Returns:
        int: The smallest multiple of ``a`` that is ``>= o``; ``o`` unchanged when
            ``a <= 1`` or ``o`` is already aligned.

    Raises:
        None: The ``a <= 1`` short-circuit returns BEFORE any ``o % a``, so a
            non-positive alignment can never raise ``ZeroDivisionError`` (Phase-2
            sec-M3 defense-in-depth; the collector already fails such values closed).

    Data Flow:
        - Return ``o`` immediately if ``a <= 1``.
        - Else compute ``o % a``; return ``o`` if already aligned, else pad up.

    Dependencies:
        Uses:
            - (none)
        Used by:
            - ``_record_layout_full_span``

    Example:
        >>> align_up(6, 4)
        8
    """
    if a <= 1:
        return o
    remainder = o % a
    return o if remainder == 0 else o + (a - remainder)


def _collect_declared_alignments(lines: list[str]) -> Optional[dict[str, int]]:
    """
    Summary:
        First pass over a RECORD_LAYOUT body: collect the declared
        ``ALIGNMENT_<CLASS> N`` directives into ``{directive_name: N}``, or return
        ``None`` (full-span-or-None) on a malformed or non-positive alignment value.

    Args:
        lines (list[str]): The RECORD_LAYOUT body lines (``layout["lines"]``); the
            ONLY input — MOD_COMMON / the module tree is never consulted (R-A).

    Returns:
        Optional[dict[str, int]]: ``{directive_name: N}`` for every well-formed
            ``ALIGNMENT_*`` line (last declaration wins on a duplicate); ``{}`` for
            a packed layout; ``None`` if any alignment value is non-int or ``< 1``.

    Raises:
        None: A non-int alignment value is caught by ``try/except`` and a
            non-positive one is rejected explicitly — both fail closed to ``None``
            so a hostile ``ALIGNMENT_WORD 0`` / ``-4`` never reaches ``align_up``
            with ``a < 1`` (Phase-2 sec-M3).

    Data Flow:
        - Iterate the lines; skip any whose token[0] is not an alignment directive.
        - For a directive line with >= 2 tokens, ``int(token[1])`` in a try/except
          returning ``None`` on failure; return ``None`` if the value is ``< 1``.
        - Record ``{directive_name: value}`` (last wins).

    Dependencies:
        Uses:
            - ``_ALIGNMENT_DIRECTIVES``
        Used by:
            - ``_record_layout_full_span``

    Example:
        >>> _collect_declared_alignments(["ALIGNMENT_WORD 2", "ALIGNMENT_LONG 4"])
        {'ALIGNMENT_WORD': 2, 'ALIGNMENT_LONG': 4}
    """
    declared: dict[str, int] = {}
    for line in lines or []:
        tokens = line.split()
        if not tokens or tokens[0] not in _ALIGNMENT_DIRECTIVES:
            continue
        if len(tokens) < 2:
            continue
        try:
            value = int(tokens[1])
        except (ValueError, TypeError):
            return None
        if value < 1:
            return None
        declared[tokens[0]] = value
    return declared


#: RECORD_LAYOUT body components that carry input values in the encode
#: direction (R5) — the encode consumes the operator's physical sequence for
#: these and only these; ``NO_AXIS_PTS_*`` / ``NO_RESCALE_X`` placeholders and
#: ``RESERVED`` padding occupy bytes but take no value (zero-filled).
_VALUE_COMPONENTS = frozenset({"AXIS_PTS_X", "AXIS_PTS_Y", "AXIS_PTS_Z", "FNC_VALUES"})


def _walk_record_layout_components(layout: dict, axis_counts: list[int]) -> Optional[list[dict]]:
    """
    Summary:
        Walk EVERY line of a RECORD_LAYOUT body into ordered per-component
        entries with accumulated on-disk offsets (R5), or return ``None``
        (full-span-or-None) if any line, datatype, or needed axis count is
        unclassifiable. This is the per-component generalization of the former
        first-line-only read: each entry records the component name, its ASAM
        position index, datatype, direction (FNC_VALUES only), the aligned
        start ``offset``, the element ``count``, the element ``size``, and the
        exclusive ``end`` offset.

    Args:
        layout (dict): A ``record_layouts_by_name`` entry; ``layout["lines"]``
            are the raw RECORD_LAYOUT body lines. Per line, token[0] is the
            component name and token[2] is the datatype — token[1] is the ASAM
            POSITION INDEX, never a count.
        axis_counts (list[int]): Ordered axis point-counts ``[n_x, n_y, n_z]``.

    Returns:
        Optional[list[dict]]: One entry per summable component, in body order,
        each ``{"component", "position", "datatype", "direction", "offset",
        "count", "size", "end"}``; the last entry's ``end`` is the record's
        full byte span. ``None`` on any unclassifiable non-empty line, unknown
        datatype, truncated component, missing axis count, malformed or
        non-positive alignment/RESERVED value, or an over-cap total. An empty
        list means the body carried no summable component.

    Raises:
        None: every failure mode degrades to ``None``/an empty list (never a
        wrong-but-non-None structure → no false-green from an under-reported
        span). ``ALIGNMENT_*`` lines are consumed as padding directives and a
        loose ``DIRECT`` line (the operator's tool emits it standalone) repeats
        the FNC_VALUES conversion flag — it carries no bytes and is skipped,
        NOT forced to ``None`` (R5).

    Data Flow:
        - First pass: ``_collect_declared_alignments(layout["lines"])`` →
          ``{directive: N}`` (or ``None`` on a malformed/non-positive value,
          which propagates full-span-or-None). A packed layout yields ``{}``.
        - Walk every body line with a running ``offset``: skip empty lines,
          ``ALIGNMENT_*`` directives, and a standalone ``DIRECT``; classify the
          rest via the §2.5 taxonomy keyed on ``axis_counts`` (NO_AXIS_PTS /
          NO_RESCALE → 1; AXIS_PTS_X/Y/Z → the axis count; FNC_VALUES →
          ``math.prod(axis_counts)`` with ``tokens[3]`` as direction;
          RESERVED → its declared ``IndexCount``, failing closed when the
          count is missing, non-int, or < 1); resolve ``tokens[2]`` via
          ``DATATYPE_SIZES.get``.
        - Per component: ``offset = align_up(offset, alignment)`` (the declared
          value for the datatype's R-B class, else 1), then emit the entry and
          advance ``offset += size × count``. Bail to ``None`` on any
          unrecognised line, truncated component, unknown datatype, missing
          axis count, or over-cap total.

    Dependencies:
        Uses:
            - ``DATATYPE_SIZES`` / ``MAX_A2L_DECODE_BYTES``
            - ``_collect_declared_alignments`` / ``_DATATYPE_ALIGNMENT_DIRECTIVE``
            - ``align_up`` / ``math.prod``
        Used by:
            - ``_record_layout_full_span``
            - ``_resolve_record_layout_components``
            - ``_encode_curve_record_bytes`` (R5 encode)

    Example:
        >>> _walk_record_layout_components(
        ...     {"lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE", "FNC_VALUES 3 SWORD ROW_DIR"]},
        ...     [8],
        ... )[-1]["end"]
        25
    """
    declared = _collect_declared_alignments(layout.get("lines") or [])
    if declared is None:
        return None  # a malformed / non-positive ALIGNMENT_* value → full-span-or-None
    components: list[dict] = []
    offset = 0
    for line in layout.get("lines") or []:
        tokens = line.split()
        if not tokens:
            continue
        component = tokens[0]
        if component in _ALIGNMENT_DIRECTIVES:
            continue  # an alignment directive, already consumed in the first pass
        if component == "DIRECT" and len(tokens) == 1:
            continue  # R5: a loose DIRECT repeats the FNC_VALUES conversion flag; no bytes
        direction = None
        if component in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y", "NO_AXIS_PTS_Z", "NO_RESCALE_X"):
            element_count = 1
        elif component == "AXIS_PTS_X":
            if len(axis_counts) < 1:
                return None
            element_count = axis_counts[0]
        elif component == "AXIS_PTS_Y":
            if len(axis_counts) < 2:
                return None
            element_count = axis_counts[1]
        elif component == "AXIS_PTS_Z":
            if len(axis_counts) < 3:
                return None
            element_count = axis_counts[2]
        elif component == "FNC_VALUES":
            element_count = math.prod(axis_counts)
            direction = tokens[3] if len(tokens) > 3 else None
        elif component == "RESERVED":
            # RESERVED <pos> <datatype> <IndexCount> occupies real bytes; a
            # missing/garbage count must fail closed (skipping it would
            # UNDER-REPORT the span), so it is validated, not ignored.
            if len(tokens) < 4:
                return None
            try:
                element_count = int(tokens[3])
            except (ValueError, TypeError):
                return None
            if element_count < 1:
                return None
        else:
            # A non-empty, non-alignment line that is not a classifiable
            # component forces full-span-or-None: an unmodeled component or a
            # standalone comment. Skipping it would UNDER-REPORT the true span
            # → a false-green.
            return None
        if len(tokens) < 3:
            return None  # recognised component missing its datatype token
        datatype = tokens[2]
        size = DATATYPE_SIZES.get(datatype)
        if size is None:
            return None
        try:
            position = int(tokens[1])
        except (ValueError, TypeError):
            position = None  # the position index carries no bytes; a garbage one must not kill the walk
        # R-B: pad this component's start up to its datatype's declared alignment
        # (an undeclared class → alignment 1 → no padding). R-C: no trailing pad.
        alignment = declared.get(_DATATYPE_ALIGNMENT_DIRECTIVE.get(datatype), 1)
        offset = align_up(offset, alignment)
        components.append(
            {
                "component": component,
                "position": position,
                "datatype": datatype,
                "direction": direction,
                "offset": offset,
                "count": element_count,
                "size": size,
                "end": offset + size * element_count,
            }
        )
        offset += size * element_count
        if offset > MAX_A2L_DECODE_BYTES:
            return None
    return components


def _resolve_record_layout_components(
    layout_name: Optional[str],
    record_layouts_by_name: dict[str, dict],
    axis_counts: list[int],
) -> Optional[dict]:
    """
    Summary:
        Resolve a named RECORD_LAYOUT into the R5 per-component walk — the
        additive companion of :func:`_resolve_record_layout` (which keeps its
        shipped scalar shape untouched). Where the scalar resolver answers
        "what datatype is the decode unit", this one answers "where does every
        component live in the record".

    Args:
        layout_name (Optional[str]): The CHARACTERISTIC's deposit
            (``tag["record_layout_name"]`` / ``tag["deposit"]``).
        record_layouts_by_name (dict[str, dict]): The RECORD_LAYOUT side table.
        axis_counts (list[int]): Ordered axis point-counts for the walk.

    Returns:
        Optional[dict]: ``{"name", "components", "byte_size",
        "decode_endian"}`` — ``byte_size`` is the last component's exclusive
        ``end`` (the full record span, no trailing pad); ``None`` when the name
        is empty, the layout is absent, or the walk fails full-span-or-None.

    Raises:
        None: every failure mode degrades to ``None``.

    Data Flow:
        - Look the layout up by name; ``None`` on a miss.
        - ``_walk_record_layout_components(layout, axis_counts)``; ``None``/[]
          on failure or an empty body.
        - Assemble the additive descriptor.

    Dependencies:
        Uses:
            - ``_walk_record_layout_components``
        Used by:
            - R5 consumers (curve encode, future curve decode E9)

    Example:
        >>> _resolve_record_layout_components("RL", {"RL": {"lines": ["FNC_VALUES 1 UWORD ROW_DIR"]}}, [1])["byte_size"]
        2
    """
    if not layout_name:
        return None
    layout = record_layouts_by_name.get(layout_name)
    if not layout:
        return None
    components = _walk_record_layout_components(layout, axis_counts)
    if not components:
        return None
    return {
        "name": layout_name,
        "components": components,
        "byte_size": components[-1]["end"],
        "decode_endian": layout.get("byte_order"),
    }


def _record_layout_full_span(layout: dict, axis_counts: list[int]) -> Optional[int]:
    """
    Summary:
        Sum a CURVE/MAP's on-disk byte span from its resolved RECORD_LAYOUT and
        the ordered inline axis counts, or return ``None`` (full-span-or-None) if
        any component, datatype, or needed axis count is unclassifiable.

    Args:
        layout (dict): A ``record_layouts_by_name`` entry; ``layout["lines"]`` are
            the raw RECORD_LAYOUT body lines. Per line, token[0] is the component
            name and token[2] is the datatype — token[1] is the ASAM POSITION
            INDEX, never a count.
        axis_counts (list[int]): Ordered inline axis point-counts ``[n_x, n_y, n_z]``
            from ``_inline_axis_counts``.

    Returns:
        Optional[int]: The total byte span (Σ ``size × element_count`` over
            recognised components) when EVERY non-empty line is a classifiable
            summable component and the running total stays within
            ``MAX_A2L_DECODE_BYTES``; else ``None``.

    Raises:
        None: An unrecognised non-alignment line, an unknown datatype, a
            truncated component, an absent needed axis count, a malformed or
            non-positive alignment value, an empty contribution, or an over-cap
            total all degrade to ``None`` (never a wrong-but-non-None length → no
            false-green from an under-reported span). ``ALIGNMENT_*`` lines are
            consumed as padding directives, not forced to ``None`` (batch-56).

    Data Flow:
        - Delegate the whole walk to ``_walk_record_layout_components`` (the R5
          per-component walker this function now sits on top of) and take the
          last component's exclusive ``end`` — the record span with NO trailing
          pad-to-max-alignment (R-C reading (i)).
        - R5 deltas carried by the walker (this function's contract is otherwise
          unchanged): a loose ``DIRECT`` line is skipped instead of forcing
          ``None`` (the operator's tool emits it standalone), and ``RESERVED
          <pos> <dt> <IndexCount>`` is summed with its declared count instead
          of forcing ``None``.

    Dependencies:
        Uses:
            - ``_walk_record_layout_components``
        Used by:
            - ``extract_a2l_tags`` post-axis-walk length pass
            - the R5 external-axis post-pass in ``extract_a2l_tags``

    Example:
        >>> _record_layout_full_span(
        ...     {"lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE", "FNC_VALUES 3 SWORD"]},
        ...     [8],
        ... )
        25
    """
    components = _walk_record_layout_components(layout, axis_counts)
    if not components:
        return None
    return components[-1]["end"]


def _decode_scalar(raw: bytes, decode_type: str, decode_endian: str) -> Any:
    if decode_type == "FLOAT16_IEEE":
        return None
    code = DATATYPE_STRUCT_CODES.get(decode_type)
    if not code:
        return None
    prefix = ">" if decode_endian == "big" else "<"
    return struct.unpack(f"{prefix}{code}", raw)[0]


def _decode_raw_value(raw_bytes: bytes, decode_type: str, element_count: int, decode_endian: str) -> tuple[Any, str]:
    """Decode raw bytes as scalar or array based on layout metadata."""
    size = DATATYPE_SIZES.get(decode_type)
    if size is None or size <= 0:
        return None, f"unsupported decode type {decode_type}"
    expected = size * max(1, element_count)
    if len(raw_bytes) != expected:
        return None, f"size mismatch expected={expected} got={len(raw_bytes)}"
    if element_count <= 1:
        return _decode_scalar(raw_bytes, decode_type, decode_endian), ""
    values: list[Any] = []
    for index in range(element_count):
        start = index * size
        values.append(_decode_scalar(raw_bytes[start : start + size], decode_type, decode_endian))
    return values, ""


def _extract_raw_bytes(mem_map: Optional[Dict[int, int]], address: Optional[int], byte_size: Optional[int]) -> dict:
    if mem_map is None:
        return {"raw_bytes": None, "raw_available": False, "missing_ranges": [], "overlap_conflict": False}
    if address is None or byte_size is None or byte_size <= 0:
        return {"raw_bytes": None, "raw_available": False, "missing_ranges": [], "overlap_conflict": False}
    if byte_size > MAX_A2L_DECODE_BYTES:
        return {"raw_bytes": None, "raw_available": False, "missing_ranges": [], "overlap_conflict": False}
    missing: list[int] = []
    values: list[int] = []
    for offset in range(byte_size):
        current = address + offset
        if current not in mem_map:
            missing.append(current)
            values.append(0)
            continue
        values.append(mem_map[current] & 0xFF)
    return {
        "raw_bytes": bytes(values) if not missing else None,
        "raw_available": len(missing) == 0,
        "missing_ranges": missing,
        "overlap_conflict": False,
    }


def _table_lookup(value: float, table: dict, interpolate: bool) -> tuple[Any, str]:
    entries = table.get("entries") or []
    if not entries:
        return None, "lookup table is empty"
    if not interpolate:
        for raw_x, raw_y in entries:
            if raw_x == value:
                return raw_y, ""
        nearest = min(entries, key=lambda item: abs(item[0] - value))
        return nearest[1], ""
    if value <= entries[0][0]:
        return entries[0][1], ""
    if value >= entries[-1][0]:
        return entries[-1][1], ""
    for left, right in zip(entries, entries[1:]):
        lx, ly = left
        rx, ry = right
        if lx <= value <= rx:
            lyf = _to_float(ly)
            ryf = _to_float(ry)
            if lyf is None or ryf is None:
                return ly, ""
            if rx == lx:
                return lyf, ""
            ratio = (value - lx) / (rx - lx)
            return lyf + ratio * (ryf - lyf), ""
    return None, "value outside interpolation range"


def _apply_compu_method(
    raw_value: Any,
    method: Optional[dict],
    compu_tables_by_name: dict[str, dict],
    limits: Optional[tuple[Optional[float], Optional[float]]] = None,
) -> tuple[Any, str, str]:
    """Apply one COMPU_METHOD in the decode direction (raw → physical).

    ``limits`` carries the tag's declared ``(lower_limit, upper_limit)`` in
    physical units; a RAT_FUNC with two real roots takes the one inside them
    when exactly one is (LLR-158.2). Callers without tag limits pass ``None``
    (the smaller-magnitude root then wins).
    """
    if raw_value is None:
        return None, "missing", "raw value unavailable"
    if isinstance(raw_value, list):
        return raw_value, "array", ""
    if method is None:
        return raw_value, "identity_fallback", "compu method missing"
    conversion_type = str(method.get("conversion_type") or "").upper()
    if conversion_type == "IDENTICAL":
        return raw_value, "ok", ""
    if conversion_type == "LINEAR":
        coeffs = method.get("coeffs_linear") or [1.0, 0.0]
        a = coeffs[0] if coeffs and coeffs[0] is not None else 1.0
        b = coeffs[1] if len(coeffs) > 1 and coeffs[1] is not None else 0.0
        return (a * raw_value) + b, "ok", ""
    if conversion_type == "RAT_FUNC":
        physical, rat_error = _invert_rat_func(float(raw_value), method, limits)
        if physical is None:
            return None, "error", rat_error or "RAT_FUNC inversion failed"
        return physical, "ok", ""
    if conversion_type in {"TAB_NOINTP", "TAB_INTP"}:
        table_name = method.get("compu_tab_ref")
        table = compu_tables_by_name.get(table_name or "")
        if table is None:
            return None, "error", "lookup table missing"
        table_value, table_error = _table_lookup(float(raw_value), table, conversion_type == "TAB_INTP")
        if table_error:
            return None, "error", table_error
        return table_value, "ok", ""
    if conversion_type == "FORM":
        return None, "unsupported", "FORM conversion is not supported"
    return raw_value, "unknown_method", f"unsupported conversion type {conversion_type}"


#: The float datatypes the physical→raw encode packs directly (no integrality
#: or integer-range limb). ``FLOAT16_IEEE`` is deliberately ABSENT — the
#: shipped decode refuses it too (:func:`_decode_scalar` returns ``None``), so
#: the encode cannot round-trip a direction the decode does not ship.
_FLOAT_ENCODE_DATATYPES = frozenset({"FLOAT32_IEEE", "FLOAT64_IEEE"})


def _eval_rat_func(physical: float, method: dict) -> tuple[Optional[float], str]:
    """Evaluate one RAT_FUNC COMPU_METHOD in the encode direction (physical → raw).

    ASAP2 declares INT = f(PHYS) = (a·P² + b·P + c) / (d·P² + e·P + f) with
    COEFFS ``a b c d e f``; the encode computes it directly. Returns
    ``(raw, "")`` or ``(None, reason)``.
    """
    coeffs = method.get("coeffs") or []
    padded = [
        (coeffs[i] if i < len(coeffs) and coeffs[i] is not None else 0.0)
        for i in range(6)
    ]
    a, b, c, d, e, f = padded
    numerator = (a * (physical**2)) + (b * physical) + c
    denominator = (d * (physical**2)) + (e * physical) + f
    if math.isclose(denominator, 0.0):
        return None, "RAT_FUNC denominator is zero"
    return numerator / denominator, ""


def _invert_rat_func(
    raw_value: float,
    method: dict,
    limits: Optional[tuple[Optional[float], Optional[float]]] = None,
) -> tuple[Optional[float], str]:
    """Invert one RAT_FUNC COMPU_METHOD for the decode direction (raw → physical).

    The A2L declares INT = f(PHYS) = (a·P² + b·P + c) / (d·P² + e·P + f); the
    decode solves f(P) = raw for P — the quadratic (a − r·d)P² + (b − r·e)P +
    (c − r·f) = 0. Two real roots take the one inside the tag's declared
    physical ``limits`` when exactly one is, else the smaller-magnitude root.
    Returns ``(physical, "")`` or ``(None, reason)``.
    """
    coeffs = method.get("coeffs") or []
    padded = [
        (coeffs[i] if i < len(coeffs) and coeffs[i] is not None else 0.0)
        for i in range(6)
    ]
    a, b, c, d, e, f = padded
    quad_a = a - raw_value * d
    quad_b = b - raw_value * e
    quad_c = c - raw_value * f
    if math.isclose(quad_a, 0.0):
        if math.isclose(quad_b, 0.0):
            return None, "RAT_FUNC has no solution for this value"
        root = -quad_c / quad_b
        if math.isclose(
            (d * root * root) + (e * root) + f, 0.0, rel_tol=0.0, abs_tol=1e-12
        ):
            return None, "RAT_FUNC root has a zero denominator"
        return root, ""
    discriminant = quad_b * quad_b - 4.0 * quad_a * quad_c
    if discriminant < 0.0:
        return None, "RAT_FUNC has no real root for this value"
    root = math.sqrt(discriminant)
    first = (-quad_b + root) / (2.0 * quad_a)
    second = (-quad_b - root) / (2.0 * quad_a)
    if math.isclose(first, second, rel_tol=0.0, abs_tol=1e-12):
        first = second = (first + second) / 2.0
    # The quadratic comes from multiplying INT = f(PHYS) by the denominator,
    # so a root where d·P² + e·P + f is zero is spurious — it is not a root
    # of the declared conversion and is dropped.
    def _defined(value: float) -> bool:
        denom = (d * value * value) + (e * value) + f
        return not math.isclose(denom, 0.0, rel_tol=0.0, abs_tol=1e-12)

    candidates = [
        value for value in (first, second) if _defined(value)
    ]
    if not candidates:
        return None, "RAT_FUNC root has a zero denominator"
    lower = limits[0] if limits else None
    upper = limits[1] if limits else None

    def _inside(value: float) -> bool:
        if lower is not None and value < lower:
            return False
        if upper is not None and value > upper:
            return False
        return True

    inside = [value for value in candidates if _inside(value)]
    if len(inside) == 1:
        return inside[0], ""
    return min(candidates, key=abs), ""


def _reverse_table_lookup(
    physical: float, table: dict, interpolate: bool
) -> tuple[Optional[float], str, Optional[str]]:
    """Invert one COMPU_TAB (physical → raw), LLR-158.3.

    ``TAB_NOINTP`` refuses a value that is not exactly a table value, naming
    the two nearest table values. ``TAB_INTP`` refuses a value outside the
    table's physical range, naming the range; inside it, the value is
    inverse-interpolated between the bracketing entries to a fractional raw
    and the nearest integer raw is returned, with a flag naming the physical
    value that will actually be written whenever it differs from the typed
    one. Non-numeric entries are skipped; a table with no numeric entries
    refuses. Returns ``(raw, "", flag_or_None)`` or ``(None, reason, None)``.
    """
    numeric: list[tuple[float, float]] = []
    for raw_x, raw_y in table.get("entries") or []:
        y = _to_float(raw_y)
        if y is not None:
            numeric.append((float(raw_x), y))
    if not numeric:
        return None, "lookup table has no numeric entries", None
    if not interpolate:
        for raw_x, y in numeric:
            if math.isclose(y, physical, rel_tol=0.0, abs_tol=1e-9):
                return raw_x, "", None
        by_proximity = sorted(numeric, key=lambda item: abs(item[1] - physical))
        named = sorted({y for _, y in by_proximity[:2]})
        if len(named) == 1:
            nearest_text = str(named[0])
        else:
            nearest_text = f"{named[0]} and {named[1]}"
        return None, (
            f"the value {physical} is not a table value - "
            f"the nearest table values are {nearest_text}"
        ), None
    numeric.sort(key=lambda item: item[1])
    y_min = numeric[0][1]
    y_max = numeric[-1][1]
    if physical < y_min or physical > y_max:
        return None, (
            f"the value {physical} is outside the table range "
            f"[{y_min}, {y_max}]"
        ), None
    for raw_x, y in numeric:
        if math.isclose(y, physical, rel_tol=0.0, abs_tol=1e-9):
            return raw_x, "", None
    # ASAM TAB_INTP: inverse-interpolate the physical value between the two
    # bracketing entries to a fractional raw, then write the nearest integer
    # raw (decoding it forward names the physical value actually written).
    raw_fraction: Optional[float] = None
    for (left_raw, left_y), (right_raw, right_y) in zip(numeric, numeric[1:]):
        if left_y <= physical <= right_y and not math.isclose(
            right_y, left_y, rel_tol=0.0, abs_tol=1e-12
        ):
            raw_fraction = left_raw + (physical - left_y) * (
                right_raw - left_raw
            ) / (right_y - left_y)
            break
    if raw_fraction is None:
        return None, (
            f"the value {physical} is not invertible in this table"
        ), None
    raw_x = round(raw_fraction)
    written, _ = _table_lookup(float(raw_x), table, True)
    written_f = _to_float(written)
    if written_f is None:
        return None, "lookup table has no numeric entries", None
    if math.isclose(written_f, physical, rel_tol=0.0, abs_tol=1e-9):
        return float(raw_x), "", None
    return float(raw_x), "", (
        f"the value {physical} is not a table value - "
        f"the write proceeds as {written_f}"
    )


def _invert_physical_to_raw(
    physical: float,
    method: Optional[dict],
    compu_tabs_by_name: Optional[dict],
) -> tuple[Optional[float], Optional[str]]:
    """
    Summary:
        The COMPU_METHOD encode direction (physical → raw) — one inversion per
        conversion limb, shared by the scalar encoder
        (:func:`encode_physical_to_raw_bytes`) and the R5 curve-record encoder
        (:func:`_encode_curve_record_bytes`). Extracted so both encode paths
        invert byte-identically.

    Args:
        physical (float): The physical-unit value.
        method (Optional[dict]): The resolved COMPU_METHOD side-table entry, or
            ``None`` (the no-COMPU_METHOD limb → identity).
        compu_tabs_by_name (Optional[dict]): The COMPU_TAB side table (the
            ``TAB_NOINTP`` / ``TAB_INTP`` inversion input).

    Returns:
        tuple[Optional[float], Optional[str], list[str]]: ``(raw, None,
        flags)`` on success — the flags carry non-fatal conversion limbs (an
        in-range ``TAB_INTP`` value whose nearest table entry decodes to a
        different physical value: the flag names the written value).
        ``(None, reason, [])`` on refusal — the reason names the limb,
        exactly as the scalar encoder's shipped refusals name them.

    Raises:
        None: every limb is a returned reason.

    Data Flow:
        - ``method is None`` → identity (mirrors the decode's
          ``identity_fallback``); ``IDENTICAL`` → identity.
        - ``LINEAR`` → ``raw = (physical − b) / a``; ``a == 0`` refuses.
        - ``RAT_FUNC`` → :func:`_eval_rat_func` (INT = f(PHYS) directly);
          a zero denominator refuses.
        - ``TAB_NOINTP`` / ``TAB_INTP`` → :func:`_reverse_table_lookup`
          (LLR-158.3): ``TAB_NOINTP`` refuses a non-table value naming the
          two nearest; ``TAB_INTP`` refuses a value outside the table range
          naming the range, and flags an in-range off-grid write naming the
          physical value that will be written; missing/empty/non-numeric
          table refuses.
        - ``FORM`` / unknown conversion type on a DEFINED method → REFUSE.

    Dependencies:
        Uses:
            - ``_eval_rat_func`` / ``_reverse_table_lookup``
        Used by:
            - ``encode_physical_to_raw_bytes`` / ``_encode_curve_record_bytes``

    Example:
        >>> _invert_physical_to_raw(110.0, {"conversion_type": "LINEAR", "coeffs_linear": [2.0, 10.0]}, None)
        (50.0, None, [])
    """
    if method is None:
        return physical, None, []  # the identity limb (no COMPU_METHOD)
    conversion_type = str(method.get("conversion_type") or "").upper()
    if conversion_type == "IDENTICAL":
        return physical, None, []
    if conversion_type == "LINEAR":
        coeffs = method.get("coeffs_linear") or []
        lin_a = coeffs[0] if len(coeffs) > 0 and coeffs[0] is not None else 1.0
        lin_b = coeffs[1] if len(coeffs) > 1 and coeffs[1] is not None else 0.0
        if math.isclose(lin_a, 0.0):
            return None, "LINEAR conversion coefficient a is zero", []
        return (physical - lin_b) / lin_a, None, []
    if conversion_type == "RAT_FUNC":
        raw, rat_error = _eval_rat_func(physical, method)
        if raw is None:
            return None, rat_error or "RAT_FUNC evaluation failed", []
        return raw, None, []
    if conversion_type in {"TAB_NOINTP", "TAB_INTP"}:
        table = (compu_tabs_by_name or {}).get(
            str(method.get("compu_tab_ref") or "")
        )
        if table is None or not table.get("entries"):
            return None, "lookup table missing or empty", []
        raw, tab_error, tab_flag = _reverse_table_lookup(
            physical, table, conversion_type == "TAB_INTP"
        )
        if raw is None:
            return None, tab_error or "table inversion failed", []
        return raw, None, [tab_flag] if tab_flag else []
    # FORM (the decode's own unsupported limb) and every unknown conversion
    # type on a DEFINED method.
    return None, f"conversion type {conversion_type!r} is not supported", []


def _encode_curve_record_bytes(
    tag: dict,
    values: list[Any],
    compu_methods_by_name: Optional[dict],
    compu_tabs_by_name: Optional[dict],
    record_layouts_by_name: Optional[dict],
) -> tuple[Optional[tuple[int, ...]], Optional[str], list[str]]:
    """
    Summary:
        R5 array limb of the physical→raw encode: pack a CURVE/MAP physical
        SEQUENCE into ONE record through the per-component RECORD_LAYOUT walk
        — axis points and FNC_VALUES land at their accumulated, alignment-padded
        offsets in the tag's byte order, and non-value components
        (``NO_AXIS_PTS_*`` / ``RESERVED``) are zero-filled. This is what lets
        the Patch Editor patch a curve by symbol.

    Args:
        tag (dict): One CHARACTERISTIC row (CURVE/MAP) of the tag map — needs
            ``axis_meta`` (inline axes), ``record_layout_name`` /
            ``deposit``, ``effective_byte_order``, ``length``, and the usual
            COMPU_METHOD / limit fields.
        values (list[Any]): The physical sequence — axis points (X, then Y/Z)
            followed by the FNC_VALUES, in layout component order. For a
            multi-axis ``COL_DIR`` MAP the caller pre-orders the function
            values column-major: no reordering is performed (R5 ships CURVE
            unambiguous; MAP ordering is the caller's contract).
        compu_methods_by_name (Optional[dict]): The COMPU_METHOD side table.
        compu_tabs_by_name (Optional[dict]): The COMPU_TAB side table.
        record_layouts_by_name (Optional[dict]): The RECORD_LAYOUT side table.

    Returns:
        tuple[Optional[tuple[int, ...]], Optional[str], list[str]]: ``(bytes,
        None, flags)`` — ``bytes`` spans the full walk (last component's
        ``end``), padding included. ``(None, reason, [])`` on refusal.

    Raises:
        None: every limb is a returned reason.

    Data Flow:
        - The MATRIX_DIM > 1 limb is refused as in the scalar path.
        - Axis counts come from ``_inline_axis_counts`` and the components from
          ``_walk_record_layout_components``; ANY resolution failure returns
          the SHIPPED arrays refusal ("array values are not supported") — the
          additive encode accepts nothing that refused before R5.
        - The sequence length must equal Σ counts over the value-bearing
          components (``AXIS_PTS_*`` / ``FNC_VALUES``); a mismatch refuses
          naming both numbers.
        - ``FLOAT16_IEEE`` / code-less datatypes refuse (mirroring the scalar
          datatype gate); tag ``length`` must equal the record span (the
          length-drift limb, span-sized).
        - Per value: ``_invert_physical_to_raw`` (the shared COMPU_METHOD
          inversion — the tag's ONE method applies to axis points and function
          values alike; per-axis AXIS_DESCR conversions are an R5-known
          limit), then the finite / integrality / integer-range limbs per the
          component's own datatype, then ``struct.pack`` into the buffer at
          ``offset + index × size``.
        - Out-of-limits values FLAG and proceed (the scalar path's flag limb).

    Dependencies:
        Uses:
            - ``_inline_axis_counts`` / ``_walk_record_layout_components``
            - ``_VALUE_COMPONENTS`` / ``_invert_physical_to_raw``
            - ``DATATYPE_SIZES`` / ``DATATYPE_STRUCT_CODES`` / ``_FLOAT_ENCODE_DATATYPES`` / ``_to_float``
        Used by:
            - ``encode_physical_to_raw_bytes`` (the R5 dispatch)

    Example:
        >>> tag = {"axis_meta": [{"header_tokens": ["STD_AXIS"], "max_axis_points": "3", "external": False}],
        ...        "record_layout_name": "RL", "effective_byte_order": "little", "length": 10}
        >>> layouts = {"RL": {"lines": ["AXIS_PTS_X 1 UBYTE", "ALIGNMENT_WORD 2", "FNC_VALUES 2 UWORD ROW_DIR"]}}
        >>> _encode_curve_record_bytes(tag, [10, 20, 30, 100, 200, 300], None, None, layouts)[0]
        (10, 20, 30, 0, 100, 0, 200, 0, 300, 0)
    """
    matrix_dim = tag.get("matrix_dim")
    if (
        isinstance(matrix_dim, int)
        and not isinstance(matrix_dim, bool)
        and matrix_dim > 1
    ):
        return None, "matrix/array-typed tags are not supported", []
    axis_counts = _inline_axis_counts(tag.get("axis_meta") or [])
    if axis_counts is None:
        return None, "array values are not supported", []
    layout_name = str(tag.get("record_layout_name") or tag.get("deposit") or "")
    layout = (record_layouts_by_name or {}).get(layout_name)
    components = _walk_record_layout_components(layout, axis_counts) if layout else None
    if not components:
        return None, "array values are not supported", []
    value_components = [c for c in components if c["component"] in _VALUE_COMPONENTS]
    expected = sum(c["count"] for c in value_components)
    if len(values) != expected:
        return None, (
            f"the record needs {expected} values (axis points + function "
            f"values), got {len(values)}"
        ), []
    for component in value_components:
        if component["datatype"] == "FLOAT16_IEEE":
            return None, "datatype FLOAT16_IEEE is not supported", []
    method_name = str(tag.get("compu_method_name") or tag.get("conversion") or "")
    method: Optional[dict] = None
    if method_name and method_name != "NO_COMPU_METHOD":
        method = (compu_methods_by_name or {}).get(method_name)
    span = components[-1]["end"]
    tag_length = tag.get("length")
    if (
        isinstance(tag_length, int)
        and not isinstance(tag_length, bool)
        and tag_length != span
    ):
        return None, (
            f"tag length {tag_length} drifts from the record span {span}"
        ), []
    endian = str(tag.get("effective_byte_order") or "little")
    prefix = ">" if endian == "big" else "<"
    buffer = bytearray(span)
    flags: list[str] = []
    lower_limit = _to_float(tag.get("lower_limit"))
    upper_limit = _to_float(tag.get("upper_limit"))
    cursor = 0
    for component in value_components:
        datatype = component["datatype"]
        code = DATATYPE_STRUCT_CODES.get(datatype)
        size = component["size"]
        if code is None:
            return None, f"unsupported datatype {datatype!r}", []
        is_float = datatype in _FLOAT_ENCODE_DATATYPES
        if not is_float:
            bits = size * 8
            signed = code.islower()
            lo = -(1 << (bits - 1)) if signed else 0
            hi = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        for index in range(component["count"]):
            item = values[cursor]
            cursor += 1
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                return None, "the value is not numeric", []
            physical = float(item)
            raw, conversion_error, conversion_flags = _invert_physical_to_raw(
                physical, method, compu_tabs_by_name
            )
            if conversion_error is not None:
                return None, conversion_error, []
            flags.extend(conversion_flags)
            if not math.isfinite(raw):
                return None, "the converted raw value is not finite", []
            if is_float:
                packed_value: Any = raw
            else:
                nearest = round(raw)
                if not math.isclose(raw, nearest, rel_tol=0.0, abs_tol=1e-6):
                    return None, f"the converted raw value {raw} is not integral", []
                if not lo <= nearest <= hi:
                    return None, (
                        f"the converted raw value {nearest} is outside the "
                        f"{datatype} range"
                    ), []
                packed_value = nearest
            try:
                packed = struct.pack(f"{prefix}{code}", packed_value)
            except (struct.error, OverflowError) as exc:
                return None, f"the raw value does not pack as {datatype}: {exc}", []
            start = component["offset"] + index * size
            buffer[start : start + size] = packed
            if (lower_limit is not None and physical < lower_limit) or (
                upper_limit is not None and physical > upper_limit
            ):
                flags.append(
                    f"the value {physical} is outside the tag's declared "
                    f"limits [{lower_limit}, {upper_limit}] - the write proceeds"
                )
    return tuple(buffer), None, flags


def encode_physical_to_raw_bytes(
    tag: dict,
    physical_value: Any,
    compu_methods_by_name: Optional[dict] = None,
    compu_tabs_by_name: Optional[dict] = None,
    record_layouts_by_name: Optional[dict] = None,
) -> tuple[Optional[tuple[int, ...]], Optional[str], list[str]]:
    """Encode one physical-unit value to raw wire bytes for an A2L tag.

    Summary:
        The physical→raw ENCODE direction of the change-5 symbol form
        (batch-95 LLR-141.1, HLR-141) — net-new composition on the shipped
        COMPU_METHOD side tables (the DECODE ships since batch-91 as
        :func:`_apply_compu_method`; P-17). The operator authors a patch
        value in physical units; this helper converts it to the raw byte run
        the change-set entry carries, so the canonical writer emits
        bytes-form + symbol and shipped v2.0 readers apply it byte-identically.

    Args:
        tag (dict): One row of the tag map (:func:`extract_a2l_tags` shape) —
            needs ``datatype`` (or a resolvable record layout), ``length``,
            ``effective_byte_order``, ``compu_method_name`` /
            ``conversion``, and ``lower_limit`` / ``upper_limit``.
        physical_value (Any): The value in physical units — a plain int or
            float (what the picker hands over after parsing the operator's
            text). A list/tuple is the R5 array limb: accepted ONLY for a
            CURVE/MAP whose RECORD_LAYOUT resolves per-component (packed into
            one record via :func:`_encode_curve_record_bytes`); refused
            everywhere else exactly as before.
        compu_methods_by_name (Optional[dict]): The parse payload's
            COMPU_METHOD side table (``a2l.py``'s ``extract_compu_methods``
            shape). ``None`` is the no-COMPU_METHOD limb (identity).
        compu_tabs_by_name (Optional[dict]): The COMPU_TAB side table, the
            encode input for ``TAB_NOINTP`` / ``TAB_INTP`` conversions.
        record_layouts_by_name (Optional[dict]): The RECORD_LAYOUT side
            table — the datatype fallback mirroring the shipped enrichment
            (``tag["datatype"] or layout["decode_type"]``).

    Returns:
        tuple[Optional[tuple[int, ...]], Optional[str], list[str]]: ``(raw
        bytes, None, flags)`` on success — the flags carry non-fatal limbs
        (value outside limits: the write PROCEEDS, flagged). ``(None,
        reason, [])`` on refusal — the reason names the limb. Limb table
        (the settled design):
          - no COMPU_METHOD / ``NO_COMPU_METHOD`` / method not in the side
            tables → IDENTITY (raw = physical), mirroring the decode's
            ``identity_fallback``;
          - ``IDENTICAL`` → identity;
          - ``LINEAR`` → raw = (physical − b) / a; ``a == 0`` refuses;
          - ``RAT_FUNC`` → direct evaluation INT = f(PHYS)
            (:func:`_eval_rat_func`, LLR-158.2); a zero denominator refuses;
          - ``TAB_NOINTP`` / ``TAB_INTP`` → reverse table lookup
            (:func:`_reverse_table_lookup`, LLR-158.3): a non-table
            ``TAB_NOINTP`` value refuses naming the two nearest; a
            ``TAB_INTP`` value outside the table range refuses naming the
            range; an in-range value encodes the nearest raw and FLAGS when
            the written physical value differs from the typed one;
            missing/empty/non-numeric table refuses;
          - ``FORM`` / unknown conversion type on a DEFINED method →
            REFUSE (``FORM`` is the decode's own unsupported limb);
          - non-numeric value → REFUSE;
          - non-finite or non-integral raw (integer datatypes) → REFUSE;
          - raw outside the datatype's integer range → REFUSE;
          - length drift (tag ``length`` ≠ datatype size) → REFUSE;
          - arrays (``MATRIX_DIM`` > 1, a non-VALUE ``char_type``, or a
            list/tuple value) → REFUSE — the R5 exception: a list/tuple on a
            CURVE/MAP with a resolvable per-component layout ENCODES (one
            packed record); when that layout/axis resolution fails, the
            shipped "array values are not supported" refusal is kept;
          - unsupported datatype (incl. ``FLOAT16_IEEE``) → REFUSE;
          - value outside the tag's limits → FLAG, proceed.

    Raises:
        None: Every limb is a returned reason; the helper never raises on
        untrusted tag/value content.

    Dependencies:
        Uses:
            - _invert_physical_to_raw (the shared COMPU_METHOD inversion)
            - _encode_curve_record_bytes (the R5 CURVE/MAP array limb)
            - DATATYPE_SIZES / DATATYPE_STRUCT_CODES / _to_float
        Used by:
            - services.change_service.resolve_symbol_entry (the Patch
              Editor picker's backend, LLR-141.2)
    """
    # --- the arrays limb -----------------------------------------------------
    char_type = str(tag.get("char_type") or "").upper()
    if isinstance(physical_value, (list, tuple)):
        # R5: a CURVE/MAP whose RECORD_LAYOUT resolves per-component accepts a
        # physical SEQUENCE (axis points + FNC_VALUES) and packs ONE record.
        # Every other case keeps the shipped refusal byte-for-byte — above all
        # a CURVE/MAP whose layout/axes do NOT resolve still answers "array
        # values are not supported" (the helper fails closed to it).
        if char_type in ("CURVE", "MAP"):
            return _encode_curve_record_bytes(
                tag,
                list(physical_value),
                compu_methods_by_name,
                compu_tabs_by_name,
                record_layouts_by_name,
            )
        return None, "array values are not supported", []
    if char_type and char_type != "VALUE":
        return None, f"characteristic type {char_type!r} is not a scalar VALUE", []
    matrix_dim = tag.get("matrix_dim")
    if (
        isinstance(matrix_dim, int)
        and not isinstance(matrix_dim, bool)
        and matrix_dim > 1
    ):
        return None, "matrix/array-typed tags are not supported", []

    # --- the non-numeric limb ------------------------------------------------
    if isinstance(physical_value, bool) or not isinstance(
        physical_value, (int, float)
    ):
        return None, "the value is not numeric", []

    # --- the datatype gate (mirrors the enrichment's decode_type resolution) -
    layout_meta: Optional[dict] = None
    layout_name = str(tag.get("record_layout_name") or tag.get("deposit") or "")
    if layout_name and record_layouts_by_name:
        layout_meta = _resolve_record_layout(layout_name, record_layouts_by_name)
    datatype = str(
        tag.get("datatype") or (layout_meta or {}).get("decode_type") or ""
    ).upper()
    if not datatype:
        return None, "the tag declares no datatype", []
    if datatype == "FLOAT16_IEEE":
        return None, "datatype FLOAT16_IEEE is not supported", []
    code = DATATYPE_STRUCT_CODES.get(datatype)
    size = DATATYPE_SIZES.get(datatype)
    if code is None or size is None:
        return None, f"unsupported datatype {datatype!r}", []
    element_count = (layout_meta or {}).get("element_count") or 1
    if element_count > 1:
        return None, "array-typed tags are not supported", []

    # --- the COMPU_METHOD encode direction -----------------------------------
    method_name = str(tag.get("compu_method_name") or tag.get("conversion") or "")
    method: Optional[dict] = None
    if method_name and method_name != "NO_COMPU_METHOD":
        method = (compu_methods_by_name or {}).get(method_name)
    physical = float(physical_value)
    raw, conversion_error, conversion_flags = _invert_physical_to_raw(
        physical, method, compu_tabs_by_name
    )
    if conversion_error is not None:
        return None, conversion_error, []

    # --- the finite / integral / range limbs ---------------------------------
    if not math.isfinite(raw):
        return None, "the converted raw value is not finite", []
    if datatype in _FLOAT_ENCODE_DATATYPES:
        packed_value: Any = raw
    else:
        nearest = round(raw)
        if not math.isclose(raw, nearest, rel_tol=0.0, abs_tol=1e-6):
            return None, f"the converted raw value {raw} is not integral", []
        bits = size * 8
        signed = code.islower()
        lo = -(1 << (bits - 1)) if signed else 0
        hi = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        if not lo <= nearest <= hi:
            return None, (
                f"the converted raw value {nearest} is outside the "
                f"{datatype} range"
            ), []
        packed_value = nearest

    # --- the length-drift limb ------------------------------------------------
    tag_length = tag.get("length")
    if (
        isinstance(tag_length, int)
        and not isinstance(tag_length, bool)
        and tag_length != size
    ):
        return None, (
            f"tag length {tag_length} drifts from the {datatype} size {size}"
        ), []

    # --- pack in the tag's byte order (mirrors _decode_scalar) ---------------
    endian = str(tag.get("effective_byte_order") or "little")
    prefix = ">" if endian == "big" else "<"
    try:
        packed = struct.pack(f"{prefix}{code}", packed_value)
    except (struct.error, OverflowError) as exc:
        return None, f"the raw value does not pack as {datatype}: {exc}", []
    raw_bytes = tuple(packed)

    # --- the out-of-limits limb: FLAG + proceed --------------------------------
    flags: list[str] = list(conversion_flags)
    lower_limit = _to_float(tag.get("lower_limit"))
    upper_limit = _to_float(tag.get("upper_limit"))
    if (lower_limit is not None and physical < lower_limit) or (
        upper_limit is not None and physical > upper_limit
    ):
        flags.append(
            f"the value {physical} is outside the tag's declared limits "
            f"[{lower_limit}, {upper_limit}] - the write proceeds"
        )
    return raw_bytes, None, flags


def extract_a2l_tags(
    sections: list[dict],
    record_layouts_by_name: Optional[dict[str, dict]] = None,
    compu_methods_by_name: Optional[dict[str, dict]] = None,
    errors: Optional[list[str]] = None,
) -> list[dict]:
    """Extract MEASUREMENT and CHARACTERISTIC tags with ASAP2-oriented fields.

    Args:
        sections: The section tree from ``_build_section_tree_into``.
        record_layouts_by_name: The RECORD_LAYOUT map.
        compu_methods_by_name: The COMPU_METHOD map.
        errors: An error sink (``append`` is called); ``None`` drops the errors.
    """
    tags: list[dict] = []
    _errors = errors if errors is not None else []
    memory_segments = extract_memory_segments(sections)
    target_sections = {"CHARACTERISTIC", "MEASUREMENT"}
    record_layouts_by_name = record_layouts_by_name or {}
    compu_methods_by_name = compu_methods_by_name or {}
    refused_length_ids: set[int] = set()
    standing_size_ids: set[int] = set()
    post_info: dict[int, tuple] = {}

    def _module_byte_order_source(section: dict) -> tuple[Optional[str], Optional[str], Optional[int]]:
        for child in section.get("children") or []:
            if child.get("name") == "MOD_COMMON":
                return _byte_order_from_words(_section_words(child))
        return None, None, None

    # Pre-pass: the byte-order source (order, word, line) of every RECORD_LAYOUT.
    layout_sources: dict[str, tuple] = {}

    def _collect_layout_sources(nodes: list[dict]) -> None:
        for node in nodes:
            if node.get("name") == "RECORD_LAYOUT":
                layout_name = parse_begin_meta(node.get("meta", "") or "")[0]
                layout_sources[layout_name] = _byte_order_from_words(_section_words(node))
            _collect_layout_sources(node.get("children") or [])

    _collect_layout_sources(sections)

    def _process_tag(section: dict, module_byte_order: Optional[str], module_source: tuple) -> None:
        section_name = section.get("name", "")
        start_line = section.get("start_line")
        end_line = section.get("end_line")

        stream = _section_words(section)
        head = list(itertools.islice(stream, 10))
        name, long_id, header, rest = _tag_header(section_name, head)
        name_count = rest - len(header)

        # A quoted name word holding a character outside U+0021 … U+007E (E3S-10).
        if head and head[0][0].startswith('"'):
            for ch in _unquote(head[0][0]):
                code = ord(ch)
                if not (_ECHO_OK_MIN <= code <= _ECHO_OK_MAX):
                    _errors.append(f"Line {head[0][1]}: unexpected character U+{code:04X}")
                    break

        if end_line is None:
            _errors.append(f"Line {start_line}: {section_name} {_echo_word(name)} is not closed")
            return

        header_m = 6 if section_name == "MEASUREMENT" else 7
        if 1 <= len(header) <= header_m - 1:
            _errors.append(
                f"Line {start_line}: {section_name} {_echo_word(name)} has "
                f"{len(header)} of its {header_m} header words"
            )

        tag: dict = {
            "section": section_name,
            "name": name,
            "description": long_id,
            "address": None,
            "length": None,
            "source": "assigned",
            "unit": None,
            "lower_limit": None,
            "upper_limit": None,
            "bit_org": None,
            "datatype": None,
            "deposit": None,
            "conversion": None,
            "matrix_dim": None,
            "symbol_link": None,
            "display_identifier": None,
            "link_map": None,
            "memory_region": "unknown",
            "endian": None,
            "virtual": False,
            "function_group": None,
            "access": None,
            "record_layout_name": None,
            "compu_method_name": None,
            "effective_byte_order": None,
            "axis_meta": [],
            "char_type": None,
            "max_diff": None,
        }

        header_meas: Optional[dict] = None
        header_char: Optional[dict] = None
        header_address_word: Optional[str] = None
        header_address_line: Optional[int] = None
        if section_name == "MEASUREMENT":
            header_meas = parse_measurement_header(" ".join(header))
        else:
            if len(header) == 7:
                header_char = _characteristic_from_tokens(header)
                header_address_word = header[1]
                header_address_line = head[name_count + 1][1] if name_count + 1 < len(head) else start_line

        if header_meas:
            tag["datatype"] = header_meas.get("datatype")
            tag["conversion"] = header_meas.get("conversion")
            tag["lower_limit"] = header_meas.get("lower_limit")
            tag["upper_limit"] = header_meas.get("upper_limit")
            _apply_conversion_source(tag, tag.get("conversion"))
        if header_char:
            tag["char_type"] = header_char.get("char_type")
            tag["max_diff"] = header_char.get("max_diff")
            tag["deposit"] = header_char.get("deposit")
            tag["record_layout_name"] = header_char.get("deposit")
            tag["conversion"] = header_char.get("conversion")
            tag["compu_method_name"] = header_char.get("conversion")
            tag["lower_limit"] = header_char.get("lower_limit")
            tag["upper_limit"] = header_char.get("upper_limit")
            _apply_conversion_source(tag, tag.get("conversion"))

        keyword_lines = _tag_keyword_lines(itertools.chain(head[rest:], stream), errors=_errors)
        keyword_texts = [text for text, _line in keyword_lines]

        address_words: list[tuple[int, int]] = []
        address_invalid = False
        bit_mask_words: list[tuple[str, int]] = []
        byte_order_words: list[tuple[str, int]] = []
        bit_mask_missing = False
        byte_order_missing = False
        has_standing_size = False
        seen: set[str] = set()

        # The header address word is an address word (D-6 revised).
        if header_address_word is not None:
            value = _number_word(header_address_word)
            if value is None:
                _errors.append(
                    f"Line {header_address_line}: address {_echo_word(header_address_word)} is not a number"
                )
                address_invalid = True
            elif value > _MAX_ADDRESS:
                address_invalid = True
            else:
                address_words.append((value, header_address_line))

        for text, line in keyword_lines:
            parts = text.split(" ")
            kw = parts[0]
            args = parts[1:]
            if kw in seen:
                _errors.append(
                    f"Line {line}: {_echo_word(kw)} is declared twice in "
                    f"{section_name} {_echo_word(name)}"
                )
            seen.add(kw)

            if kw == "ECU_ADDRESS":
                if len(parts) == 2:
                    value = _number_word(args[0])
                    if value is None:
                        _errors.append(f"Line {line}: ECU_ADDRESS {_echo_word(args[0])} is not a number")
                        address_invalid = True
                    elif value > _MAX_ADDRESS:
                        address_invalid = True
                    else:
                        address_words.append((value, line))
                else:
                    address_invalid = True
            elif kw in ("DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE"):
                if kw in ("DATA_SIZE", "LENGTH"):
                    has_standing_size = True
                if len(parts) == 2 and _number_word(args[0]) is None:
                    _errors.append(f"Line {line}: {kw} {_echo_word(args[0])} is not a number")
            elif kw == "MATRIX_DIM":
                prod = 1
                ok = _MATRIX_DIM_MIN <= len(args) <= _MATRIX_DIM_MAX
                if ok:
                    for arg in args:
                        value = _number_word(arg)
                        if value is None:
                            _errors.append(f"Line {line}: MATRIX_DIM {_echo_word(arg)} is not a number")
                            ok = False
                            break
                        prod *= value
                tag["matrix_dim"] = prod if (ok and args) else None
            elif kw == "LOWER_LIMIT":
                if len(parts) == 2:
                    tag["lower_limit"] = args[0]
            elif kw == "UPPER_LIMIT":
                if len(parts) == 2:
                    tag["upper_limit"] = args[0]
            elif kw == "UNIT":
                if len(parts) == 2:
                    tag["unit"] = args[0]
            elif kw == "BYTE_ORDER":
                if len(parts) == 2:
                    byte_order_words.append((args[0], line))
                else:
                    byte_order_missing = True
            elif kw == "BIT_MASK":
                if len(parts) == 2:
                    bit_mask_words.append((args[0], line))
                else:
                    bit_mask_missing = True
            elif kw == "DATA_TYPE":
                if len(parts) == 2:
                    tag["datatype"] = args[0]
            elif kw == "FUNCTION":
                if len(parts) == 2:
                    tag["function_group"] = args[0]
            elif kw == "VIRTUAL":
                tag["virtual"] = True
            elif kw == "COMPU_METHOD":
                if len(parts) == 2:
                    tag["conversion"] = args[0]
                    tag["compu_method_name"] = args[0]
                    if args[0] != "NO_COMPU_METHOD":
                        tag["source"] = "formula"
            elif kw == "FORMULA":
                tag["source"] = "formula"
            elif kw == "READ_ONLY":
                tag["access"] = "read_only"
            elif kw == "CALIBRATABLE":
                tag["access"] = "calibratable"
            elif kw == "DISPLAY_IDENTIFIER":
                if len(parts) >= 2:
                    tag["display_identifier"] = args[0]
            elif kw == "SYMBOL_LINK":
                if len(parts) >= 2:
                    tag["symbol_link"] = args[0]

        # BYTE_ORDER value and source (E3S-27).
        own_bo_word: Optional[str] = None
        own_bo_line: Optional[int] = None
        own_bo_order: Optional[str] = None
        bo_values = {w for w, _ in byte_order_words}
        if byte_order_missing:
            address_invalid = True
        elif len(bo_values) > 1:
            address_invalid = True
        elif len(byte_order_words) >= 1:
            own_bo_word = byte_order_words[0][0]
            own_bo_line = byte_order_words[0][1]
            own_bo_order = _normalize_byte_order(own_bo_word)
            tag["endian"] = own_bo_word

        bm_values = {w for w, _ in bit_mask_words}
        if bit_mask_missing:
            address_invalid = True
            tag["bit_org"] = None
        elif len(bm_values) > 1:
            address_invalid = True
            tag["bit_org"] = None
        elif len(bit_mask_words) >= 1:
            tag["bit_org"] = bit_mask_words[0][0]

        # Byte-order source (own → layout → module) and effective byte order.
        layout_order, layout_word, layout_line = layout_sources.get(
            str(tag.get("record_layout_name") or ""), (None, None, None)
        )
        module_order, module_word, module_line = module_source
        if own_bo_word is not None and own_bo_order is None:
            _errors.append(f"Line {own_bo_line}: BYTE_ORDER {_echo_word(own_bo_word)} is not a byte order")
            address_invalid = True
        elif own_bo_word is None:
            if layout_word is not None and layout_order is None:
                address_invalid = True
            elif layout_word is None and module_word is not None and module_order is None:
                address_invalid = True

        effective = own_bo_order
        if effective is None:
            effective = layout_order
        if effective is None:
            effective = module_order
        if effective is None:
            effective = "little"
        tag["effective_byte_order"] = effective

        # Address (D-6 revised).
        if address_invalid:
            tag["address"] = None
        elif len(set(v for v, _ in address_words)) > 1:
            vals = sorted(set(v for v, _ in address_words))
            _errors.append(
                f"Line {start_line}: {section_name} {_echo_word(name)} declares the "
                f"addresses 0x{vals[0]:08X} and 0x{vals[-1]:08X}"
            )
            tag["address"] = None
        elif address_words:
            tag["address"] = address_words[0][0]

        lm = collect_link_maps(section)
        if lm:
            tag["link_map"] = lm

        for child in section.get("children") or []:
            if child.get("name") == "AXIS_DESCR":
                axis_tokens = _flatten_body_tokens(child.get("lines") or [])
                tag["axis_meta"].append(
                    {
                        "name": parse_begin_meta(child.get("meta", "") or "")[0],
                        "header_tokens": axis_tokens,
                        "max_axis_points": axis_tokens[3] if len(axis_tokens) > 3 else None,
                        "external": "AXIS_PTS_REF" in axis_tokens,
                    }
                )

        # Length (CTX *length rows*; a refusal is final).
        kind = tag.get("char_type")
        if section_name == "MEASUREMENT":
            element_size = DATATYPE_SIZES.get(tag.get("datatype"))
        else:
            element_size = _characteristic_element_size(
                str(tag.get("deposit") or ""), record_layouts_by_name
            )
        span: Optional[int] = None
        if section_name == "CHARACTERISTIC" and kind in ("CURVE", "MAP"):
            axis_counts = _inline_axis_counts(tag.get("axis_meta") or [])
            if axis_counts is not None:
                layout = record_layouts_by_name.get(str(tag.get("record_layout_name") or ""))
                if layout:
                    span = _record_layout_full_span(layout, axis_counts)

        agree, smallest, largest, no_number = _tag_sizes(keyword_lines, element_size, kind, span)
        if no_number:
            refused_length_ids.add(id(tag))
            tag["length"] = None
        elif not agree:
            _errors.append(
                f"Line {start_line}: {section_name} {_echo_word(name)} declares the "
                f"sizes {smallest} and {largest}"
            )
            refused_length_ids.add(id(tag))
            tag["length"] = None
        else:
            if section_name == "MEASUREMENT":
                tag["length"] = _infer_length_measurement(keyword_texts, header_meas)
            else:
                tag["length"] = _infer_length_characteristic(
                    keyword_texts, header_char, record_layouts_by_name
                )
            if tag["length"] is not None:
                bounded = _bounded_length(tag["length"])
                if bounded is None:
                    _errors.append(
                        f"Line {start_line}: {section_name} {_echo_word(name)} has the "
                        f"length {tag['length']}, outside 1 to 1048576 bytes"
                    )
                    refused_length_ids.add(id(tag))
                tag["length"] = bounded

        # Inline-axis span (base behavior; a refusal is final).
        if (
            section_name == "CHARACTERISTIC"
            and kind in ("CURVE", "MAP")
            and tag.get("length") is None
            and id(tag) not in refused_length_ids
            and span is not None
        ):
            tag["length"] = span

        # Remember a standing DATA_SIZE/LENGTH whose span is external (E3S-29).
        if (
            section_name == "CHARACTERISTIC"
            and kind in ("CURVE", "MAP")
            and has_standing_size
            and span is None
            and id(tag) not in refused_length_ids
        ):
            standing_size_ids.add(id(tag))
            post_info[id(tag)] = (keyword_lines, element_size, kind)

        if not tag.get("compu_method_name"):
            token = tag.get("conversion")
            if token and token in compu_methods_by_name:
                tag["compu_method_name"] = token

        tag["memory_region"] = classify_address(tag.get("address"), memory_segments)
        tags.append(tag)

    def walk(section_list: list[dict], enclosing_byte_order: Optional[str], module_source: tuple) -> None:
        for section in section_list:
            name = section.get("name", "")
            current_module_byte_order = enclosing_byte_order
            current_module_source = module_source
            if name == "MODULE":
                order, word, line = _module_byte_order_source(section)
                if word is not None and order is None:
                    _errors.append(f"Line {line}: BYTE_ORDER {_echo_word(word)} is not a byte order")
                current_module_byte_order = order if order is not None else enclosing_byte_order
                current_module_source = (order, word, line)
            elif name == "RECORD_LAYOUT":
                layout_name = parse_begin_meta(section.get("meta", "") or "")[0]
                order, word, line = layout_sources.get(layout_name, (None, None, None))
                if word is not None and order is None:
                    _errors.append(f"Line {line}: BYTE_ORDER {_echo_word(word)} is not a byte order")
            if name in target_sections:
                _process_tag(section, current_module_byte_order, current_module_source)
            if section.get("children"):
                walk(section["children"], current_module_byte_order, current_module_source)

    walk(sections, None, (None, None, None))

    # External-axis post-pass (base) + the standing-size span comparison (E3S-29).
    for tag in tags:
        tid = id(tag)
        if tid in refused_length_ids:
            continue
        if not (tag.get("section") == "CHARACTERISTIC" and tag.get("char_type") in ("CURVE", "MAP")):
            continue
        counts = _axis_counts_resolving_external(tag.get("axis_meta") or [], tags)
        if counts is None:
            continue
        layout = record_layouts_by_name.get(str(tag.get("record_layout_name") or ""))
        if not layout:
            continue
        span = _record_layout_full_span(layout, counts)
        if tag.get("length") is None:
            tag["length"] = span
        elif tid in standing_size_ids:
            keyword_lines, element_size, kind = post_info[tid]
            agree, smallest, largest, _no_number = _tag_sizes(keyword_lines, element_size, kind, span)
            if not agree:
                _errors.append(
                    f"Line {tag.get('start_line')}: CHARACTERISTIC {_echo_word(tag.get('name'))} "
                    f"declares the sizes {smallest} and {largest}"
                )
                tag["length"] = None
                refused_length_ids.add(tid)
    return tags


def extract_declared_spans(
    sections: list[dict], record_layouts_by_name: Optional[dict[str, dict]] = None
) -> list[dict]:
    """List the BLOB and INSTANCE declared spans (name, kind, address, length)."""
    spans: list[dict] = []
    record_layouts_by_name = record_layouts_by_name or {}
    typedefs: dict[str, dict] = {}

    def _collect_typedefs(nodes: list[dict]) -> None:
        for node in nodes:
            name = node.get("name", "")
            if name.startswith("TYPEDEF_"):
                stream = _section_words(node)
                head = list(itertools.islice(stream, 10))
                tname, _tlongid, theader, trest = _tag_header(name, head)
                keyword_lines = _tag_keyword_lines(itertools.chain(head[trest:], stream))
                typedefs[tname] = {"kind": name, "header": theader, "keyword_lines": keyword_lines}
            _collect_typedefs(node.get("children") or [])

    _collect_typedefs(sections)

    def _instance_length(typedef: Optional[dict], matrix_product: Optional[int]) -> Optional[int]:
        if typedef is None or matrix_product is None:
            return None
        kind = typedef["kind"]
        header = typedef["header"]
        kw_lines = typedef["keyword_lines"]
        if kind == "TYPEDEF_MEASUREMENT":
            datatype = header[0] if header else None
            tmatrix = _matrix_dim_product(kw_lines)
            if datatype in DATATYPE_SIZES and tmatrix is not None:
                return _bounded_length(DATATYPE_SIZES[datatype] * tmatrix * matrix_product)
            return None
        if kind == "TYPEDEF_CHARACTERISTIC":
            char_type = header[0] if header else None
            deposit = header[2] if len(header) > 2 else None
            if char_type in ("VALUE", "VAL_BLK", "ASCII"):
                hdr = {"char_type": char_type, "deposit": deposit}
                kw_texts = [text for text, _line in kw_lines]
                base = _infer_length_characteristic(kw_texts, hdr, record_layouts_by_name)
                if base is None:
                    return None
                return _bounded_length(base * matrix_product)
            return None
        if kind in ("TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"):
            size_word = header[0] if header else None
            size = _number_word(size_word) if size_word is not None else None
            if size is None:
                return None
            return _bounded_length(size * matrix_product)
        return None

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            name = node.get("name", "")
            if name == "BLOB":
                head = list(itertools.islice(_section_words(node), 4))
                bname, _longid, bheader, _rest = _tag_header("BLOB", head)
                address = _number_word(bheader[0]) if len(bheader) >= 1 else None
                length = _number_word(bheader[1]) if len(bheader) >= 2 else None
                spans.append(
                    {"name": bname, "kind": "BLOB", "address": address, "length": _bounded_length(length)}
                )
            elif name == "INSTANCE":
                stream = _section_words(node)
                head = list(itertools.islice(stream, 4))
                iname, _longid, iheader, irest = _tag_header("INSTANCE", head)
                typedef_name = iheader[0] if len(iheader) >= 1 else None
                address = _number_word(iheader[1]) if len(iheader) >= 2 else None
                keyword_lines = _tag_keyword_lines(itertools.chain(head[irest:], stream))
                matrix_product = _matrix_dim_product(keyword_lines)
                spans.append(
                    {
                        "name": iname,
                        "kind": "INSTANCE",
                        "address": address,
                        "length": _instance_length(typedefs.get(typedef_name), matrix_product),
                    }
                )
            walk(node.get("children") or [])

    walk(sections)
    return spans


def parse_a2l_file(path: Path, progress: Optional[A2LProgress] = None) -> dict:
    """
    Summary:
        Parse an A2L file into section tree, extracted tags, and parse diagnostics.

    Args:
        path (Path): Path to A2L file on disk.
        progress (Optional[A2LProgress]): Optional callback reporting ``(bytes_consumed, total_bytes)``
            during the section-tree read; ``None`` disables reporting.

    Returns:
        dict: Payload with ``path``, ``sections``, ``errors``, and ``tags`` keys.

    Raises:
        OSError: Re-raised for read errors other than missing file from section parsing.

    Data Flow:
        - Build section tree and structural errors via ``build_section_tree``.
        - Extract tags from section tree using ASAP2 field parsers.
        - Return parser payload dictionary used by TUI and validation layer.
        - Emit stage timing and size logs for load diagnostics.

    Dependencies:
        Uses:
            - ``build_section_tree``
            - ``extract_a2l_tags``
            - ``extract_memory_segments``
        Used by:
            - ``S19TuiApp`` A2L load paths
            - tests in ``tests/test_tui_a2l.py``
    """
    parse_started = time.perf_counter()
    errors = _CappedErrors()
    sections = _build_section_tree_into(path, progress, errors)
    tag_started = time.perf_counter()
    record_layouts_by_name = extract_record_layouts(sections)
    compu_methods_by_name = extract_compu_methods(sections)
    compu_tabs_by_name = extract_compu_tables(sections)
    tags = extract_a2l_tags(
        sections,
        record_layouts_by_name=record_layouts_by_name,
        compu_methods_by_name=compu_methods_by_name,
        errors=errors,
    )
    declared_spans = extract_declared_spans(sections, record_layouts_by_name)
    tag_elapsed = time.perf_counter() - tag_started
    parse_elapsed = time.perf_counter() - parse_started
    error_list = errors.as_list()
    segment_counts: dict[str, int] = {"flash": 0, "ram": 0, "unknown": 0}
    for segment in extract_memory_segments(sections):
        region = classify_address(segment.get("base"), [segment])
        if region in segment_counts:
            segment_counts[region] += 1
        else:
            segment_counts["unknown"] += 1
    measurement_count = len([tag for tag in tags if tag.get("section") == "MEASUREMENT"])
    characteristic_count = len([tag for tag in tags if tag.get("section") == "CHARACTERISTIC"])
    logger.info(
        "A2L parse stages: path=%s total_seconds=%.3f tag_extract_seconds=%.3f tags=%d measurement=%d characteristic=%d errors=%d",
        path,
        parse_elapsed,
        tag_elapsed,
        len(tags),
        measurement_count,
        characteristic_count,
        len(error_list),
    )
    logger.debug(
        "A2L memory segment distribution: path=%s flash=%d ram=%d unknown=%d",
        path,
        segment_counts["flash"],
        segment_counts["ram"],
        segment_counts["unknown"],
    )
    return {
        "path": str(path),
        "sections": sections,
        "errors": error_list,
        "tags": tags,
        "declared_spans": declared_spans,
        "record_layouts_by_name": record_layouts_by_name,
        "compu_methods_by_name": compu_methods_by_name,
        "compu_tabs_by_name": compu_tabs_by_name,
    }


def enrich_a2l_tags_with_values(a2l_data: dict, mem_map: Optional[Dict[int, int]]) -> list[dict]:
    """Build tag payload with decoded raw/physical values and conversion status."""
    source_tags = a2l_data.get("tags", [])
    record_layouts_by_name = a2l_data.get("record_layouts_by_name", {})
    compu_methods_by_name = a2l_data.get("compu_methods_by_name", {})
    compu_tabs_by_name = a2l_data.get("compu_tabs_by_name", {})
    enriched: list[dict] = []
    for tag in source_tags:
        layout_name = str(tag.get("record_layout_name") or tag.get("deposit") or "")
        layout_meta = _resolve_record_layout(layout_name, record_layouts_by_name)
        decode_type = tag.get("datatype") or (layout_meta or {}).get("decode_type")
        element_count = (layout_meta or {}).get("element_count") or 1
        if tag.get("length") is None:
            byte_size = None
        else:
            byte_size = (layout_meta or {}).get("byte_size") or tag.get("length")
        decode_endian = str(tag.get("effective_byte_order") or (layout_meta or {}).get("decode_endian") or "little")

        memory = _extract_raw_bytes(mem_map, tag.get("address"), byte_size)
        raw_value = None
        decode_error = ""
        if memory["raw_available"] and decode_type:
            raw_value, decode_error = _decode_raw_value(
                memory["raw_bytes"],
                str(decode_type),
                int(element_count),
                decode_endian,
            )

        method_name = str(tag.get("compu_method_name") or tag.get("conversion") or "")
        method = compu_methods_by_name.get(method_name)
        compu_method_unit = None
        if isinstance(method, dict):
            compu_method_unit = method.get("unit")
        physical_value, conversion_status, conversion_error = _apply_compu_method(
            raw_value,
            method,
            compu_tabs_by_name,
            limits=(
                _to_float(tag.get("lower_limit")),
                _to_float(tag.get("upper_limit")),
            ),
        )
        lower_limit = _to_float(tag.get("lower_limit"))
        upper_limit = _to_float(tag.get("upper_limit"))
        physical_number = _to_float(physical_value)
        outside_limits = bool(
            physical_number is not None
            and ((lower_limit is not None and physical_number < lower_limit) or (upper_limit is not None and physical_number > upper_limit))
        )

        enriched.append(
            {
                **tag,
                "decode_type": decode_type,
                "element_count": element_count,
                "byte_size": byte_size,
                "decode_endian": decode_endian,
                "raw_bytes": memory["raw_bytes"].hex() if memory["raw_bytes"] else None,
                "raw_available": memory["raw_available"],
                "missing_ranges": memory["missing_ranges"],
                "overlap_conflict": memory["overlap_conflict"],
                "raw_value": raw_value,
                "decode_error": decode_error,
                "physical_value": physical_value,
                "conversion_status": conversion_status,
                "conversion_error": conversion_error,
                "value_outside_limits": outside_limits,
                "compu_method_unit": compu_method_unit,
            }
        )
    return enriched


#: Axis component names in walk order — index i belongs to axis i.
_AXIS_COMPONENT_NAMES = ("AXIS_PTS_X", "AXIS_PTS_Y", "AXIS_PTS_Z")


def _decode_component_run(
    raw_bytes: bytes,
    component: dict,
    decode_endian: str,
) -> tuple[Optional[list[Any]], Optional[str]]:
    """Decode one walked RECORD_LAYOUT component into a list of raw values.

    Thin slice over :func:`_decode_raw_value` that always returns a LIST
    (the E9 description pairs element i of every run) and maps a
    ``FLOAT16_IEEE`` element (the shipped decode refuses it) to an honest
    ``None`` + reason instead of raising.
    """
    size = int(component.get("size") or 0)
    count = int(component.get("count") or 0)
    if size <= 0 or count <= 0:
        return None, "component carries no decodable elements"
    chunk = raw_bytes[int(component["offset"]) : int(component["end"])]
    if len(chunk) != size * count:
        return None, f"record too short for {component['component']}: {len(chunk)} of {size * count} bytes"
    values: list[Any] = []
    for index in range(count):
        start = index * size
        item = _decode_scalar(chunk[start : start + size], str(component["datatype"]), decode_endian)
        if item is None:
            return None, f"datatype {component['datatype']} is not decodable"
        values.append(item)
    return values, None


def _axis_compu_method(axis: dict, compu_methods_by_name: dict[str, dict]) -> Optional[dict]:
    """Resolve an axis's own COMPU_METHOD from its AXIS_DESCR header tokens."""
    header_tokens = axis.get("header_tokens") or []
    if len(header_tokens) < 3:
        return None
    name = header_tokens[2]
    if not name or name == "NO_COMPU_METHOD":
        return None
    return compu_methods_by_name.get(name)


def describe_curve_tag(
    tag: dict,
    a2l_data: Optional[dict],
    mem_map: Optional[Dict[int, int]],
) -> dict:
    """Build the E9 parameter description for one CHARACTERISTIC (batch-96).

    Summary:
        Combines the A2L metadata (name, COMPU_METHOD description/unit/
        conversion type, limits, per-axis type and max points) with the
        current S19/HEX image bytes: the record is sliced at the R5-walked
        component offsets and every axis point / function value is decoded
        and converted to physical units point by point (the shipped
        :func:`_apply_compu_method` + :func:`_table_lookup`, exactly the
        decode direction the enrichment uses). For a single-axis CURVE the
        result pairs into an ``x -> y`` point table.

    Args:
        tag (dict): One CHARACTERISTIC row — the raw parse tag or an
            enriched row both work (enrichment keys are read best-effort).
        a2l_data (Optional[dict]): The parse payload (``compu_methods_by_name``
            / ``compu_tabs_by_name`` / ``record_layouts_by_name`` / ``tags``).
        mem_map (Optional[Dict[int, int]]): The loaded image's byte map.

    Returns:
        dict: The description model. ``status`` is one of ``ok`` /
            ``not_a_curve`` / ``axes_unresolved`` / ``layout_unresolved`` /
            ``no_memory`` — an unresolved layout, an external axis without
            a resolvable count, or missing image bytes NEVER raise and
            never invent data; the payload carries the honest reason in
            ``notes`` and whatever partial structure resolved.

    Raises:
        None: every limb degrades to a status + note.
    """
    a2l_data = a2l_data or {}
    compu_methods_by_name = a2l_data.get("compu_methods_by_name") or {}
    compu_tabs_by_name = a2l_data.get("compu_tabs_by_name") or {}
    record_layouts_by_name = a2l_data.get("record_layouts_by_name") or {}
    tags = a2l_data.get("tags") or []

    char_type = str(tag.get("char_type") or "").upper()
    method_name = str(tag.get("compu_method_name") or tag.get("conversion") or "")
    method: Optional[dict] = None
    if method_name and method_name != "NO_COMPU_METHOD":
        method = compu_methods_by_name.get(method_name)
    lower_limit = _to_float(tag.get("lower_limit"))
    upper_limit = _to_float(tag.get("upper_limit"))

    description: dict = {
        "name": tag.get("name"),
        "long_identifier": tag.get("description"),
        "char_type": char_type or None,
        "address": tag.get("address"),
        "byte_size": tag.get("length"),
        "unit": (method or {}).get("unit") if method else tag.get("unit"),
        "lower_limit": lower_limit,
        "upper_limit": upper_limit,
        "compu_method_name": method_name or None,
        "compu_description": (method or {}).get("long_identifier"),
        "conversion_type": (method or {}).get("conversion_type") if method else None,
        "axes": [],
        "points": None,
        "notes": [],
        "status": "ok",
    }
    if method is None and method_name and method_name != "NO_COMPU_METHOD":
        description["notes"].append(
            f"compu method {method_name!r} not found - raw values shown"
        )

    if char_type not in ("CURVE", "MAP"):
        # E9 is a CURVE/MAP surface; a scalar tag gets an honest header
        # (never a crash) and its current value when the row is enriched.
        description["status"] = "not_a_curve"
        description["scalar_raw"] = tag.get("raw_value")
        description["scalar_phys"] = tag.get("physical_value")
        if tag.get("physical_value") is None and tag.get("raw_value") is not None:
            # the bytes are present but the conversion refused them (UX-C8):
            # the modal reads the short enum-derived reason, never A2L text
            description["scalar_reason"] = _short_decode_reason(
                tag.get("conversion_status"), tag.get("conversion_error")
            )
        return description

    axis_meta = tag.get("axis_meta") or []
    axis_counts = _axis_counts_resolving_external(axis_meta, tags)
    if axis_counts is None:
        description["status"] = "axes_unresolved"
        if not axis_meta:
            description["notes"].append("the characteristic declares no AXIS_DESCR axes")
        else:
            description["notes"].append(
                "axis point counts could not be resolved (external axis "
                "reference dangling or a non-numeric MaxAxisPoints) - "
                "the record shape is unknown"
            )
        return description

    layout_name = str(tag.get("record_layout_name") or tag.get("deposit") or "")
    resolved = _resolve_record_layout_components(layout_name, record_layouts_by_name, axis_counts)
    if resolved is None:
        description["status"] = "layout_unresolved"
        description["notes"].append(
            f"record layout {layout_name!r} does not resolve per-component "
            "- point decoding is unavailable"
        )
        for axis, count in zip(axis_meta, axis_counts):
            description["axes"].append(
                {
                    "kind": (axis.get("header_tokens") or [None])[0],
                    "max_axis_points": count,
                    "external": bool(axis.get("external")),
                }
            )
        return description

    byte_size = resolved["byte_size"]
    description["byte_size"] = byte_size
    memory = _extract_raw_bytes(mem_map, tag.get("address"), byte_size)
    if not memory["raw_available"] or memory["raw_bytes"] is None:
        description["status"] = "no_memory"
        missing = len(memory["missing_ranges"])
        description["notes"].append(
            "the record bytes are not fully present in the loaded image "
            f"({missing} of {byte_size} bytes missing at "
            f"0x{(tag.get('address') or 0):X}) - values unavailable"
        )
        return description

    raw_bytes = memory["raw_bytes"]
    decode_endian = str(tag.get("effective_byte_order") or resolved.get("decode_endian") or "little")
    components = resolved["components"]

    # --- axis limbs -------------------------------------------------------
    axis_runs: list[Optional[list[Any]]] = []
    axis_converted: list[Optional[list[Any]]] = []
    for index, axis in enumerate(axis_meta):
        component_name = _AXIS_COMPONENT_NAMES[index] if index < len(_AXIS_COMPONENT_NAMES) else None
        component = next(
            (c for c in components if c["component"] == component_name),
            None,
        )
        header_tokens = axis.get("header_tokens") or []
        axis_method = _axis_compu_method(axis, compu_methods_by_name)
        axis_info: dict = {
            "kind": header_tokens[0] if header_tokens else None,
            "max_axis_points": axis_counts[index] if index < len(axis_counts) else None,
            "external": bool(axis.get("external")),
            "unit": (axis_method or {}).get("unit"),
        }
        run: Optional[list[Any]] = None
        converted: Optional[list[Any]] = None
        if component is not None:
            run, run_error = _decode_component_run(raw_bytes, component, decode_endian)
            if run is None:
                description["notes"].append(
                    f"axis {index + 1}: {run_error}"
                )
            else:
                converted = []
                for raw_item in run:
                    phys_item, conv_status, conv_error = _apply_compu_method(
                        raw_item, axis_method, compu_tabs_by_name
                    )
                    if conv_status in ("error", "unsupported", "unknown_method"):
                        description["notes"].append(
                            f"axis {index + 1}: point conversion failed: {conv_error}"
                        )
                    converted.append(phys_item)
        elif axis.get("external"):
            # The axis points live in the referenced AXIS_PTS record; decode
            # them from ITS address with the same walked-machinery.
            ref_name = None
            if "AXIS_PTS_REF" in header_tokens:
                ref_index = header_tokens.index("AXIS_PTS_REF")
                if ref_index + 1 < len(header_tokens):
                    ref_name = header_tokens[ref_index + 1]
            ref_tag = next((t for t in tags if t.get("name") == ref_name), None)
            run, converted = _decode_external_axis_points(
                ref_tag, axis_counts[index], axis_method,
                compu_tabs_by_name, record_layouts_by_name, mem_map, description,
            )
        else:
            description["notes"].append(
                f"axis {index + 1}: the layout deposits no axis points "
                "(NO_AXIS_PTS) - x is shown as the point index"
            )
        axis_info["points_raw"] = run
        axis_info["points_phys"] = converted
        description["axes"].append(axis_info)
        axis_runs.append(run)
        axis_converted.append(converted)

    # --- FNC_VALUES limb --------------------------------------------------
    fnc_component = next((c for c in components if c["component"] == "FNC_VALUES"), None)
    values_raw: Optional[list[Any]] = None
    values_phys: Optional[list[Any]] = None
    if fnc_component is None:
        description["notes"].append("the layout carries no FNC_VALUES component")
        description["status"] = "layout_unresolved"
        return description
    values_raw, fnc_error = _decode_component_run(raw_bytes, fnc_component, decode_endian)
    if values_raw is None:
        description["notes"].append(f"function values: {fnc_error}")
        description["status"] = "layout_unresolved"
        return description
    values_phys = []
    for raw_item in values_raw:
        phys_item, conv_status, conv_error = _apply_compu_method(
            raw_item, method, compu_tabs_by_name, limits=(lower_limit, upper_limit)
        )
        if conv_status in ("error", "unsupported", "unknown_method"):
            description["notes"].append(f"value conversion failed: {conv_error}")
        values_phys.append(phys_item)
    description["values_raw"] = values_raw
    description["values_phys"] = values_phys

    # --- point pairing (single-axis CURVE) --------------------------------
    expected = math.prod(axis_counts)
    if len(values_raw) != expected:
        description["notes"].append(
            f"the layout yields {len(values_raw)} function values for "
            f"{expected} axis points - the shape is inconsistent"
        )
    if len(axis_meta) == 1:
        x_run = axis_converted[0]
        points: list[dict] = []
        for index, phys_item in enumerate(values_phys):
            if x_run is not None and index < len(x_run):
                x_value = x_run[index]
                x_note = None
            else:
                x_value = index
                x_note = "index (axis points unavailable)"
            phys_number = _to_float(phys_item)
            points.append(
                {
                    "x": x_value,
                    "y": phys_item,
                    "x_raw": axis_runs[0][index] if axis_runs[0] is not None and index < len(axis_runs[0]) else None,
                    "y_raw": values_raw[index],
                    "x_note": x_note,
                    "outside_limits": bool(
                        phys_number is not None
                        and (
                            (lower_limit is not None and phys_number < lower_limit)
                            or (upper_limit is not None and phys_number > upper_limit)
                        )
                    ),
                }
            )
        description["points"] = points
    else:
        description["notes"].append(
            "multi-axis MAP: the axes and the flattened value run are "
            "listed; a 2-D grid view is not part of this description yet"
        )
    return description


def _decode_external_axis_points(
    ref_tag: Optional[dict],
    count: int,
    axis_method: Optional[dict],
    compu_tabs_by_name: dict[str, dict],
    record_layouts_by_name: dict[str, dict],
    mem_map: Optional[Dict[int, int]],
    description: dict,
) -> tuple[Optional[list[Any]], Optional[list[Any]]]:
    """Decode an external axis's points from the referenced AXIS_PTS record.

    Best-effort honest limb: a missing reference, an unresolvable ref
    layout, or absent image bytes yields ``(None, None)`` + a note — the
    caller then falls back to the point index, never invented data.
    """
    if not isinstance(ref_tag, dict):
        description["notes"].append("external axis: the AXIS_PTS reference does not resolve")
        return None, None
    ref_counts = _inline_axis_counts(ref_tag.get("axis_meta") or [])
    if ref_counts is None:
        ref_counts = [count]
    ref_layout_name = str(ref_tag.get("record_layout_name") or ref_tag.get("deposit") or "")
    ref_layout = record_layouts_by_name.get(ref_layout_name)
    ref_components = (
        _walk_record_layout_components(ref_layout, ref_counts) if ref_layout else None
    )
    ref_component = next(
        (c for c in (ref_components or []) if c["component"] in _VALUE_COMPONENTS),
        None,
    )
    if ref_component is None:
        description["notes"].append(
            f"external axis: the referenced record {ref_tag.get('name')!r} "
            "has no decodable point component"
        )
        return None, None
    ref_memory = _extract_raw_bytes(mem_map, ref_tag.get("address"), ref_component["end"])
    if not ref_memory["raw_available"] or ref_memory["raw_bytes"] is None:
        description["notes"].append(
            f"external axis: the referenced record {ref_tag.get('name')!r} "
            "bytes are not present in the image"
        )
        return None, None
    ref_endian = str(ref_tag.get("effective_byte_order") or "little")
    run, run_error = _decode_component_run(ref_memory["raw_bytes"], ref_component, ref_endian)
    if run is None:
        description["notes"].append(f"external axis: {run_error}")
        return None, None
    converted = []
    for raw_item in run:
        phys_item, _status, _error = _apply_compu_method(raw_item, axis_method, compu_tabs_by_name)
        converted.append(phys_item)
    return run, converted


def _format_point_number(value: Any) -> str:
    """Render one table cell: finite numbers tight, anything else n/a."""
    number = _to_float(value)
    if number is None:
        return "n/a"
    if isinstance(value, float) and not number.is_integer():
        return f"{number:g}"
    if isinstance(value, int):
        return str(value)
    return f"{number:g}"


#: The shipped decode's refusal strings → the short modal reason tokens
#: (UX-C8: ``Scalar value: n/a (<reason>)``). UX-C10: every token is derived
#: from this fixed enum, never from A2L text.
_DECODE_REASON_TOKENS = {
    "RAT_FUNC denominator is zero": "rat_func_denominator_zero",
    "RAT_FUNC has no real root for this value": "rat_func_no_real_root",
    "RAT_FUNC has no solution for this value": "rat_func_no_solution",
    "RAT_FUNC inversion failed": "rat_func_inversion_failed",
    "lookup table missing": "lookup_table_missing",
    "lookup table is empty": "lookup_table_empty",
    "value outside interpolation range": "value_outside_table_range",
}


def _short_decode_reason(status: Any, error: Any) -> Optional[str]:
    """Map a decode failure to its short enum-derived reason token (UX-C8)."""
    if not error:
        return None
    token = _DECODE_REASON_TOKENS.get(str(error))
    if token is not None:
        return token
    if status:
        return str(status)
    return "undecodable"


def render_curve_description(description: dict) -> str:
    """Render the E9 description model as plain text (markup=False safe).

    The modal's ``Static`` runs with ``markup=False`` (the WindowHelpScreen
    C-17 voice), so this output is verbatim fixed-width text — no Rich
    markup, no console metacharacters. Unresolved limbs render as their
    honest status line instead of a table.
    """
    lines: list[str] = []
    kind = description.get("char_type") or "CHARACTERISTIC"
    title = f"{kind}  {description.get('name') or '?'}"
    if description.get("long_identifier"):
        title += f"  -  {description['long_identifier']}"
    lines.append(title)
    address = description.get("address")
    if isinstance(address, int):
        tail = f"address 0x{address:08X}"
        byte_size = description.get("byte_size")
        if isinstance(byte_size, int):
            tail += f", {byte_size} bytes"
        lines.append(tail)
    unit = description.get("unit")
    limits = ""
    if description.get("lower_limit") is not None or description.get("upper_limit") is not None:
        limits = f" [{description.get('lower_limit')}, {description.get('upper_limit')}]"
    lines.append(f"Unit: {unit or 'n/a'}{limits}")
    conversion_bits = []
    if description.get("conversion_type"):
        conversion_bits.append(str(description["conversion_type"]))
    if description.get("compu_method_name"):
        conversion_bits.append(str(description["compu_method_name"]))
    if description.get("compu_description"):
        conversion_bits.append(f'"{description["compu_description"]}"')
    lines.append(f"Conversion: {' - '.join(conversion_bits) if conversion_bits else 'n/a'}")

    for index, axis in enumerate(description.get("axes") or []):
        axis_line = (
            f"Axis {index + 1}: {axis.get('kind') or '?'}"
            f", max {axis.get('max_axis_points') if axis.get('max_axis_points') is not None else '?'}"
            f" points"
        )
        if axis.get("external"):
            axis_line += " (external)"
        if axis.get("unit"):
            axis_line += f", unit {axis['unit']}"
        lines.append(axis_line)

    status = description.get("status")
    if status == "not_a_curve":
        scalar = description.get("scalar_phys")
        reason = description.get("scalar_reason")
        if scalar is not None:
            scalar_text = _format_point_number(scalar)
        elif reason:
            scalar_text = f"n/a ({reason})"
        else:
            scalar_text = "n/a"
        lines.append("")
        lines.append(f"Scalar value: {scalar_text} {unit or ''}".rstrip())
        lines.append("(this characteristic is not a CURVE/MAP - no point table)")
    elif status != "ok":
        lines.append("")
        lines.append(f"Status: {status} - point table unavailable")

    points = description.get("points")
    if points:
        lines.append("")
        x_cells = [_format_point_number(p["x"]) for p in points]
        y_cells = [
            _format_point_number(p["y"]) + (" (!)" if p.get("outside_limits") else "")
            for p in points
        ]
        x_width = max([len("x")] + [len(c) for c in x_cells])
        y_width = max([len("y")] + [len(c) for c in y_cells])
        all_index = all(p.get("x_note") for p in points)
        if all_index:
            lines.append("  x: point index (axis points unavailable)")
        lines.append(f"  {'x':>{x_width}}   {'y':>{y_width}}")
        for p, x_cell, y_cell in zip(points, x_cells, y_cells):
            note = (
                "" if all_index else (f"   ({p['x_note']})" if p.get("x_note") else "")
            )
            lines.append(f"  {x_cell:>{x_width}}   {y_cell:>{y_width}}{note}")
        y_numbers = [_to_float(p["y"]) for p in points]
        spark = _sparkline([n for n in y_numbers if n is not None])
        if spark:
            lines.append("")
            lines.append(f"  y shape: {spark}")
        if any(p.get("outside_limits") for p in points):
            lines.append("")
            lines.append("  (!) the value is outside the tag's declared limits")

    if description.get("values_phys") is not None and not points:
        lines.append("")
        rendered = ", ".join(_format_point_number(v) for v in description["values_phys"])
        lines.append(f"  values: {rendered}")

    notes = description.get("notes") or []
    if notes:
        lines.append("")
        for note in notes:
            lines.append(f"  note: {note}")
    return "\n".join(lines)


def _sparkline(numbers: list[float]) -> str:
    """One Unicode-block sparkline (optional E9 garnish), empty when flat/short."""
    if len(numbers) < 2:
        return ""
    lo = min(numbers)
    hi = max(numbers)
    if not math.isfinite(hi - lo) or hi == lo:
        return ""
    blocks = "▁▂▃▄▅▆▇█"
    return "".join(
        blocks[min(len(blocks) - 1, int((value - lo) / (hi - lo) * (len(blocks) - 1)))]
        for value in numbers
    )


def validate_characteristic(tag_name: str, a2l_data: dict, mem_map: Optional[Dict[int, int]]) -> dict:
    """Return detailed characteristic-level validation diagnostics."""
    tag = next((item for item in a2l_data.get("tags", []) if item.get("name") == tag_name), None)
    if tag is None:
        return {"ok": False, "name": tag_name, "errors": ["tag not found"]}
    enriched = enrich_a2l_tags_with_values({"tags": [tag], **a2l_data}, mem_map)[0]
    errors: list[str] = []
    if enriched.get("address") is None:
        errors.append("characteristic address not in S19")
    if enriched.get("record_layout_name") and enriched.get("decode_type") is None:
        errors.append("layout missing")
    if enriched.get("compu_method_name") and enriched.get("conversion_status") in {"identity_fallback", "unknown_method"}:
        errors.append("compu method missing")
    if not enriched.get("decode_endian"):
        errors.append("byte order missing")
    if enriched.get("decode_error"):
        errors.append(f"size mismatch: {enriched.get('decode_error')}")
    if enriched.get("value_outside_limits"):
        errors.append("value outside limits")
    if not enriched.get("raw_available"):
        errors.append("characteristic address not in S19")
    return {
        "ok": len(errors) == 0,
        "name": tag_name,
        "errors": errors,
        "tag": enriched,
    }


def get_raw_value(tag_name: str, a2l_data: dict, mem_map: Optional[Dict[int, int]]) -> dict:
    """Lookup one characteristic and return decoded raw value payload."""
    result = validate_characteristic(tag_name, a2l_data, mem_map)
    tag = result.get("tag") or {}
    return {
        "name": tag_name,
        "ok": result.get("ok", False),
        "raw_value": tag.get("raw_value"),
        "raw_bytes": tag.get("raw_bytes"),
        "decode_error": tag.get("decode_error"),
        "errors": result.get("errors", []),
    }


def get_physical_value(tag_name: str, a2l_data: dict, mem_map: Optional[Dict[int, int]]) -> dict:
    """Lookup one characteristic and return converted physical value payload."""
    result = validate_characteristic(tag_name, a2l_data, mem_map)
    tag = result.get("tag") or {}
    return {
        "name": tag_name,
        "ok": result.get("ok", False),
        "physical_value": tag.get("physical_value"),
        "conversion_status": tag.get("conversion_status"),
        "conversion_error": tag.get("conversion_error"),
        "errors": result.get("errors", []),
    }


def _memory_range_in_map(address: int, length: int, mem_map: Dict[int, int]) -> bool:
    """Check if a memory range is in a memory map."""
    for offset in range(length):
        if address + offset not in mem_map:
            return False
    return True


def _tag_schema_and_applicability(tag: dict) -> tuple[bool, bool, str]:
    """Return (schema_ok, memory_check_applicable, reason_if_schema_bad).

    ASAM MCD-2 MC derives a MEASUREMENT/CHARACTERISTIC size (Datatype /
    RECORD_LAYOUT), so an object whose length could not be *derived* is still
    spec-valid — only a missing *address* is a schema concern. A valid address
    with an underivable length is therefore ``schema_ok`` but not
    memory-checkable (renders white/grey, never red).
    """
    virtual = tag.get("virtual") is True
    address = tag.get("address")
    length = tag.get("length")
    if virtual and address is None:
        return True, False, ""
    if address is None:
        return False, False, "missing address/length"
    if length is None:
        return True, False, ""
    return True, True, ""


def validate_a2l_tags(tags: list[dict], mem_map: Optional[Dict[int, int]] = None) -> list[dict]:
    """Enrich tags with schema and optional image coverage (ECU range vs loaded mem_map).

    When ``mem_map`` is None, no byte-range check is performed: ``memory_checked`` is False
    and ``in_memory`` is None. When a map is given and a range applies, ``memory_checked`` is
    True and ``in_memory`` reflects full coverage.

    ``valid`` is kept as an alias for ``schema_ok`` for older call sites.
    """
    results: list[dict] = []
    for tag in tags:
        schema_ok, applicable, reason = _tag_schema_and_applicability(tag)
        if mem_map is None or not applicable:
            reason_text = reason if not schema_ok else ""
            if schema_ok and tag.get("decode_error"):
                reason_text = str(tag.get("decode_error"))
            results.append(
                {
                    **tag,
                    "schema_ok": schema_ok,
                    "memory_checked": False,
                    "in_memory": None,
                    "reason": reason_text,
                    "valid": schema_ok,
                }
            )
            continue
        addr = tag.get("address")
        ln = tag.get("length")
        if addr is None or ln is None:
            results.append(
                {
                    **tag,
                    "schema_ok": False,
                    "memory_checked": False,
                    "in_memory": None,
                    "reason": "missing address/length",
                    "valid": False,
                }
            )
            continue
        in_mem = _memory_range_in_map(addr, ln, mem_map)
        reason_text = ""
        if not in_mem:
            reason_text = "characteristic address not in S19"
        if tag.get("decode_error"):
            reason_text = str(tag.get("decode_error"))
        if tag.get("value_outside_limits"):
            reason_text = "value outside limits"
        results.append(
            {
                **tag,
                "schema_ok": True,
                "memory_checked": True,
                "in_memory": in_mem,
                "reason": reason_text,
                "valid": True,
            }
        )
    return results


def format_tag_validation_status(check: dict) -> str:
    """Short status for summary text (A2L view tile)."""
    if not check.get("schema_ok", True):
        r = (check.get("reason") or "schema").strip()
        return f"ERR ({r})" if r else "ERR"
    if check.get("memory_checked") and check.get("in_memory") is False:
        return "OUT(image)"
    if check.get("memory_checked") and check.get("in_memory") is True:
        return "OK"
    return ""


def _summary_sanitize(text: str) -> str:
    """Replace each U+0000 … U+001F, U+007F … U+009F, U+2028 and U+2029 with
    U+FFFD (R-A2L-READ.51)."""
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code <= 0x1F or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029):
            out.append("\ufffd")
        else:
            out.append(ch)
    return "".join(out)


def iter_section_lines(sections: List[dict], depth: int = 0) -> List[str]:
    """Depth-first lines for /begin tree (indented), over the canonical
    ``meta`` with control characters as U+FFFD."""
    lines: list[str] = []
    indent = "  " * depth
    for section in sections:
        name = _summary_sanitize(section.get("name", "UNKNOWN") or "UNKNOWN")
        meta = _summary_sanitize(section.get("meta", "") or "")
        start = section.get("start_line")
        end = section.get("end_line")
        label = f"{name} {meta}".strip()
        lines.append(f"{indent}- {label} (lines {start}-{end})")
        children = section.get("children") or []
        if children:
            lines.extend(iter_section_lines(children, depth + 1))
    return lines


def render_a2l_view(
    a2l_data: Optional[dict], tag_checks: Optional[list[dict]] = None, max_tag_lines: Optional[int] = None
) -> str:
    """Render a concise, human-readable A2L summary: errors, then sections,
    then tags (R-A2L-076, .077)."""
    if not a2l_data:
        return "No A2L loaded."
    errors = a2l_data.get("errors") or []
    sections = a2l_data.get("sections") or []
    tags = a2l_data.get("tags") or []
    blocks: list[str] = []
    if errors:
        blocks.append("A2L parse errors:\n" + "\n".join(_summary_sanitize(f"- {e}") for e in errors))
    if sections:
        blocks.append("A2L Sections:\n" + "\n".join(iter_section_lines(sections)))
    if tags:
        check_map = {}
        if tag_checks:
            check_map = {(item.get("section"), item.get("name")): item for item in tag_checks}
        truncated = False
        emitted_tag_lines = 0
        tag_lines: list[str] = []
        for tag in tags:
            if isinstance(max_tag_lines, int) and max_tag_lines > 0:
                if emitted_tag_lines >= max_tag_lines:
                    truncated = True
                    break
            addr = tag.get("address")
            length = tag.get("length")
            addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
            len_text = str(length) if isinstance(length, int) else "n/a"
            status = ""
            if check_map:
                match = check_map.get((tag.get("section"), tag.get("name")))
                if match is not None:
                    status = format_tag_validation_status(match)
            reg = tag.get("memory_region") or "unknown"
            tail = f" {status}" if status else ""
            tag_lines.append(
                _summary_sanitize(
                    f"- {tag.get('section')} {tag.get('name')}: {addr_text} len={len_text} mem={reg}{tail}".strip()
                )
            )
            emitted_tag_lines += 1
        if truncated:
            remaining = max(0, len(tags) - max_tag_lines)
            tag_lines.append(f"... truncated {remaining} additional tag lines ...")
        blocks.append("A2L Tags:\n" + "\n".join(tag_lines))
    if not blocks:
        return "No A2L sections found."
    return "\n\n".join(blocks)


def validate_a2l_internal_issues(a2l_data: dict, tag_checks: Optional[list[dict]] = None) -> list[ValidationIssue]:
    """
    Summary:
        Generate typed A2L internal validation issues from parsed structure and optional tag checks.

    Args:
        a2l_data (dict): Parsed A2L payload from ``parse_a2l_file``.
        tag_checks (Optional[list[dict]]): Optional enriched tags from ``validate_a2l_tags``.

    Returns:
        list[ValidationIssue]: Structural, schema, duplicate, and reference-level findings.

    Data Flow:
        - Select validation source tags (``tag_checks`` when present, otherwise raw A2L tags).
        - Delegate internal A2L rule evaluation to shared validation module.
        - Return typed issue list for UI and tests.

    Dependencies:
        Uses:
        - ``validate_a2l_structure``
        Used by:
        - Cross-validation and A2L diagnostics surfaces
    """
    source_tags = tag_checks if tag_checks is not None else a2l_data.get("tags", [])
    return validate_a2l_structure(a2l_data, tags=source_tags)
