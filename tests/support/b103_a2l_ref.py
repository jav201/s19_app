"""Independent reference reading of an A2L file (batch-103 Inc 11 oracle).

This module is the *reference* used by R-A2L-READ.48 and R-A2L-READ.49. It is
written only from the definitions and rows of
``.dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md`` (sections
"Definitions" and "Requirements" S2.1/S2.2). It imports nothing from
``s19_app`` and shares no pattern text with ``s19_app/tui/a2l.py``; a static
guard (AST and text) runs in ``tests/test_b103_a2l_reader.py`` before any case
that uses it.

The reading returned by :func:`ref_read_a2l` mirrors the reader's payload so a
field-by-field comparison is direct::

    {
        "sections": [ {name, meta, meta_line, start_line, end_line,
                       lines, line_numbers, children} ],
        "tags":     [ {name, long_identifier, address, datatype, byte_order,
                       bit_mask, matrix_dim, kind, deposit, conversion, length,
                       axis_counts, record_layout_name} ],
        "spans":    [ {name, kind, address, length} ],
        "errors":   [ (text, line_or_None) ],
    }

The lexer is a character loop (not a regex), per E3A-08.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Lexical constants (ASCII only; no shared pattern text with a2l.py).
# ---------------------------------------------------------------------------

_BLANKS = " \t\x0b\x0c"  # space, HT, VT, FF


def _is_hex_digit(ch: str) -> bool:
    return "0" <= ch <= "9" or "a" <= ch <= "f" or "A" <= ch <= "F"

# Named kinds whose name word may stand on a later line (CTX *named kind*).
_NAMED_KINDS = frozenset(
    (
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
    )
)

# Header word count per tag / span / typedef kind (graph _HEADER_WORDS).
_HEADER_WORDS = {
    "MEASUREMENT": 6,
    "CHARACTERISTIC": 7,
    "BLOB": 2,
    "INSTANCE": 2,
    "TYPEDEF_MEASUREMENT": 6,
    "TYPEDEF_CHARACTERISTIC": 6,
    "TYPEDEF_BLOB": 1,
    "TYPEDEF_STRUCTURE": 1,
    "TYPEDEF_AXIS": 6,
}

# Keyword arities (CTX-A2L-TAG *keyword*).  -1 means MATRIX_DIM (1 to 3).
_ARITY = {
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
    "MATRIX_DIM": -1,
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

# The keywords whose surplus word (a hex-like word after the argument) is an
# error and gives no value (E3S-24).
_SURPLUS_KINDS = frozenset(
    ("ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "BIT_MASK")
)

_DATATYPE_SIZES = {
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

_MAX_BYTES = 1_048_576
_NESTING_CAP = 32
_ERROR_CAP = 100

# Byte-order words, any letter case (CTX *byte-order word*).
_BYTE_ORDER_WORDS = frozenset(
    ("MSB_FIRST", "MSB_LAST", "BIG_ENDIAN", "LITTLE_ENDIAN")
)

_KIND_FAMILY = frozenset(("CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5"))


# ---------------------------------------------------------------------------
# Small predicates and helpers.
# ---------------------------------------------------------------------------


def _echo_word(word: str) -> str:
    """R-A2L-READ.66: a file word into error text (256 cap, U+FFFD, ellipsis)."""
    body = "".join(
        ch if 0x21 <= ord(ch) <= 0x7E else "\ufffd" for ch in word[:256]
    )
    return body + ("\u2026" if len(word) > 256 else "")


def _number_word(word: str) -> Optional[int]:
    """CTX *number word*: ``0x`` + 1..16 hex digits, or 1..20 ASCII decimals."""
    if word.startswith(("0x", "0X")) and len(word) > 2:
        digits = word[2:]
        if 1 <= len(digits) <= 16 and all(_is_hex_digit(c) for c in digits):
            return int(word, 16)
        return None
    if word and len(word) <= 20 and all("0" <= c <= "9" for c in word):
        return int(word, 10)
    return None


def _bounded_length(length: Optional[int]) -> Optional[int]:
    """R-A2L-READ.38 / .46: 1 .. 1_048_576, else None."""
    if isinstance(length, int) and 1 <= length <= _MAX_BYTES:
        return length
    return None


def _normalize_byte_order(word: Optional[str]) -> Optional[str]:
    raw = (word or "").strip().upper()
    if raw in ("MSB_FIRST", "BIG_ENDIAN"):
        return "big"
    if raw in ("MSB_LAST", "LITTLE_ENDIAN"):
        return "little"
    return None


def _is_quoted(word: str) -> bool:
    return word.startswith('"')


def _unquote(word: str) -> str:
    if word.startswith('"') and word.endswith('"') and len(word) >= 2:
        return word[1:-1]
    return word


def _is_hex_like(word: str) -> bool:
    """CTX *surplus word*: a number word, a word starting with a decimal digit,
    or a word of only ASCII hex digits and ``_``."""
    if not word or _is_quoted(word) or not word.isascii():
        return False
    if "0" <= word[0] <= "9":
        return True
    return all(_is_hex_digit(c) or c == "_" for c in word)


def _line_words(text: str) -> List[str]:
    """Split one canonical text into words (single spaces outside quotes)."""
    words: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] == " ":
            i += 1
        if i >= n:
            break
        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            words.append(text[i:j])
            i = j
        else:
            j = i
            while j < n and text[j] != " ":
                j += 1
            words.append(text[i:j])
            i = j
    return words


# ---------------------------------------------------------------------------
# Lexer (character loop; E3A-08).
# ---------------------------------------------------------------------------


def _ref_lex(text: str, errors: List[Tuple[str, Optional[int]]]) -> List[Tuple[int, str]]:
    """Normalize line ends, then scan char-by-char into ``(line, canonical)``.

    Returns the canonical line items; appends lexical diagnostics to ``errors``
    as ``(text, line)``. Blanks = space/HT/VT/FF; ``/*`` .. first ``*/`` and
    ``//`` .. line end are word breaks; a quoted string keeps its quotes and
    escape pairs and may span lines; an ID word holding a character outside
    U+0021 .. U+007E gives one ``unexpected character`` error.
    """
    items: List[Tuple[int, str]] = []

    def _emit(start_line: int, word: str, current: Optional[list]) -> Optional[list]:
        if current is None:
            current = [start_line, []]
        elif current[0] != start_line:
            items.append((current[0], " ".join(current[1])))
            current = [start_line, []]
        current[1].append(word)
        return current

    i = 0
    n = len(text)
    line = 1
    current: Optional[list] = None
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in _BLANKS:
            i += 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                errors.append(("comment not closed", line))
                if current is not None:
                    items.append((current[0], " ".join(current[1])))
                return items
            line += text.count("\n", i, j)
            i = j + 2
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == '"':
            j = i + 1
            start_line = line
            buf = ['"']
            closed = False
            while j < n:
                c2 = text[j]
                if c2 == "\\" and j + 1 < n and text[j + 1] != "\n":
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                if c2 == '"':
                    buf.append('"')
                    j += 1
                    closed = True
                    break
                if c2 == "\n":
                    line += 1
                buf.append(c2)
                j += 1
            if not closed:
                errors.append(("quoted string not closed", start_line))
                if current is not None:
                    items.append((current[0], " ".join(current[1])))
                return items
            current = _emit(start_line, "".join(buf), current)
            i = j
            continue
        # An ID word: stops at a blank, a line end, a quote or a comment mark.
        j = i
        while (
            j < n
            and text[j] not in _BLANKS
            and text[j] != "\n"
            and text[j] != '"'
            and not text.startswith("/*", j)
            and not text.startswith("//", j)
        ):
            j += 1
        word = text[i:j]
        if "*/" in word:
            errors.append(("*/ without /*", line))
        for wch in word:
            if not (0x21 <= ord(wch) <= 0x7E):
                errors.append(("unexpected character U+" + f"{ord(wch):04X}", line))
                break
        current = _emit(line, word, current)
        i = j
    if current is not None:
        items.append((current[0], " ".join(current[1])))
    return items


# ---------------------------------------------------------------------------
# Section tree.
# ---------------------------------------------------------------------------


def _new_section(keyword: Optional[str], start_line: int, meta_line: int) -> dict:
    return {
        "name": keyword,
        "meta": "",
        "meta_line": meta_line,
        "start_line": start_line,
        "end_line": None,
        "lines": [],
        "line_numbers": [],
        "children": [],
    }


def _promote_named_kind(section: dict) -> None:
    """E3A-01: a named kind whose keyword line held no own words takes its
    first own run as begin words (and the next run when it is a lone name
    followed by a quoted word)."""
    if section["name"] not in _NAMED_KINDS:
        return
    if section["meta"] != "":
        return
    lines = section["lines"]
    idx = next((i for i, t in enumerate(lines) if t != ""), None)
    if idx is None:
        return
    meta = lines[idx]
    meta_line = section["line_numbers"][idx]
    lines.pop(idx)
    section["line_numbers"].pop(idx)
    words = _line_words(meta)
    if (
        len(words) == 1
        and idx < len(lines)
        and lines[idx] != ""
    ):
        following = _line_words(lines[idx])
        if len(following) == 1 and _is_quoted(following[0]):
            meta = meta + " " + lines[idx]
            lines.pop(idx)
            section["line_numbers"].pop(idx)
    section["meta"] = meta
    section["meta_line"] = meta_line


def _ref_tree(
    line_items: List[Tuple[int, str]], errors: List[Tuple[str, Optional[int]]]
) -> List[dict]:
    """Build the section tree from canonical line items (whole-word /begin,
    /end, /include in any case; innermost close; the name check; the nesting
    cap; the /include diagnostic). Words outside every section are dropped."""
    flat: List[Tuple[str, int]] = []
    for ln, text in line_items:
        for w in _line_words(text):
            flat.append((w, ln))

    root = _new_section(None, 0, 0)
    stack: List[dict] = [root]
    meta_words: List[str] = []
    run: Optional[list] = None  # [line, [words]] for stack[-1]

    def flush_meta() -> None:
        nonlocal meta_words
        if meta_words:
            stack[-1]["meta"] = " ".join(meta_words)
            meta_words = []

    def flush_run() -> None:
        nonlocal run
        if run is not None and run[1]:
            stack[-1]["lines"].append(" ".join(run[1]))
            stack[-1]["line_numbers"].append(run[0])
        run = None

    def own_word(word: str, ln: int) -> None:
        nonlocal run, meta_words
        top = stack[-1]
        if top is root:
            return
        if ln == top["meta_line"] and not top.get("_child_seen", False):
            meta_words.append(word)
            return
        if run is None or run[0] != ln:
            flush_run()
            run = [ln, [word]]
        else:
            run[1].append(word)

    k = 0
    n = len(flat)
    while k < n:
        w, ln = flat[k]
        lw = w.lower()
        if lw == "/begin":
            if k + 1 >= n:
                own_word(w, ln)
                k += 1
                continue
            if len(stack) >= _NESTING_CAP + 1:  # would open deeper than 32
                errors[:] = [("sections nested deeper than 32", ln)]
                return []
            kw, kw_line = flat[k + 1]
            flush_meta()
            flush_run()
            node = _new_section(_unquote(kw), ln, kw_line)
            stack[-1]["_child_seen"] = True
            stack[-1]["children"].append(node)
            stack[-1]["lines"].append("")
            stack[-1]["line_numbers"].append(ln)
            stack.append(node)
            k += 2
            continue
        if lw == "/end":
            if k + 1 >= n:
                own_word(w, ln)
                k += 1
                continue
            name_w = flat[k + 1][0]
            name = _unquote(name_w)
            if len(stack) == 1:
                errors.append(("/end without /begin", ln))
            else:
                flush_meta()
                flush_run()
                top = stack[-1]
                if top["name"] != name:
                    errors.append(
                        (
                            "/end " + _echo_word(name)
                            + " does not close /begin " + top["name"],
                            ln,
                        )
                    )
                top["end_line"] = ln
                stack.pop()
            k += 2
            continue
        if lw == "/include":
            flush_meta()
            flush_run()
            file_word = flat[k + 1][0] if k + 1 < n else ""
            errors.append(
                (f"Line {ln}: /include " + _echo_word(_unquote(file_word)) + " is not read", ln)
            )
            own_word(w, ln)
            k += 2 if k + 1 < n else 1
            continue
        own_word(w, ln)
        k += 1

    flush_meta()
    flush_run()
    if len(stack) > 1:
        errors.append(("Unclosed /begin sections detected.", None))

    def _finalize(sections: List[dict]) -> List[dict]:
        out: List[dict] = []
        for sec in sections:
            sec.pop("_child_seen", None)
            _promote_named_kind(sec)
            sec["children"] = _finalize(sec["children"])
            out.append(sec)
        return out

    return _finalize(root["children"])


# ---------------------------------------------------------------------------
# Own words of a section.
# ---------------------------------------------------------------------------


def _section_words(section: dict) -> List[Tuple[str, int, bool]]:
    """The section's own words in file order: (word, line, is_placeholder)."""
    words: List[Tuple[str, int, bool]] = []
    if section.get("meta"):
        for w in _line_words(section["meta"]):
            words.append((w, section.get("meta_line") or section["start_line"], False))
    for text, ln in zip(section.get("lines", []), section.get("line_numbers", [])):
        if text == "":
            words.append(("", ln, True))
        else:
            for w in _line_words(text):
                words.append((w, ln, False))
    return words


# ---------------------------------------------------------------------------
# Record layouts and typedefs (REF's own, for sizing and byte order).
# ---------------------------------------------------------------------------


def _collect_by_name(sections: List[dict], target: str) -> List[dict]:
    found: List[dict] = []
    for sec in sections:
        if sec["name"] == target:
            found.append(sec)
        found.extend(_collect_by_name(sec.get("children", []), target))
    return found


def _ref_record_layouts(sections: List[dict]) -> dict:
    out: dict = {}
    for sec in _collect_by_name(sections, "RECORD_LAYOUT"):
        layout_name, _ = _parse_begin_meta(sec.get("meta", "") or "")
        lines = sec.get("lines") or []
        first = next((t for t in lines if t != ""), "")
        tokens = _line_words(first)
        decode_token = next(
            (t for t in tokens if t in _DATATYPE_SIZES), None
        )
        out[layout_name] = {
            "name": layout_name,
            "tokens": tokens,
            "decode_type": decode_token,
            "byte_order": _byte_order_of_lines(lines),
            "lines": lines,
        }
    return out


def _deposit_size(deposit: str) -> Optional[int]:
    u = (deposit or "").upper()
    markers = (
        ("__FLOAT64_IEEE_Z", 8),
        ("__FLOAT32_IEEE_Z", 4),
        ("__FLOAT16_IEEE_Z", 2),
        ("__UBYTE_Z", 1),
        ("__SBYTE_Z", 1),
        ("__UWORD_Z", 2),
        ("__SWORD_Z", 2),
        ("__ULONG_Z", 4),
        ("__SLONG_Z", 4),
    )
    for marker, size in markers:
        if marker in u:
            return size
    return _DATATYPE_SIZES.get(u)


def _byte_order_of_lines(lines: List[str]) -> Optional[str]:
    for text in lines:
        parts = _line_words(text)
        if len(parts) >= 2 and parts[0].upper() == "BYTE_ORDER":
            return _normalize_byte_order(_unquote(parts[1]))
    return None


def _parse_begin_meta(meta: str) -> Tuple[str, Optional[str]]:
    words = _line_words(meta)
    if not words:
        return ("UNKNOWN", None)
    name = _unquote(words[0])
    return (name if name else "UNKNOWN", None)


# ---------------------------------------------------------------------------
# Tag header split.
# ---------------------------------------------------------------------------


def _tag_header(
    section_name: str, words: List[Tuple[str, int, bool]]
) -> Tuple[str, Optional[str], List[str], int]:
    name = "UNKNOWN"
    long_id: Optional[str] = None
    header: List[str] = []
    i = 0
    n = len(words)
    if i < n and not words[i][2]:
        name = _unquote(words[i][0])
        i += 1
    if i < n and not words[i][2] and _is_quoted(words[i][0]):
        value = _unquote(words[i][0])
        long_id = value if value != "" else None
        i += 1
    max_hdr = _HEADER_WORDS[section_name]
    while i < n and len(header) < max_hdr:
        w, ln, ph = words[i]
        if ph or w in _ARITY:
            break
        header.append(w)
        i += 1
    return name, long_id, header, i


# ---------------------------------------------------------------------------
# Keyword lines (argument words, arity, surplus).
# ---------------------------------------------------------------------------


def _keyword_items(
    words: List[Tuple[str, int, bool]],
    start: int,
    errors: List[Tuple[str, Optional[int]]],
) -> List[Tuple[str, List[str], List[str], int]]:
    """Return ``(keyword, args, surplus, line)`` for each keyword from ``start``."""
    items: List[Tuple[str, List[str], List[str], int]] = []
    i = start
    n = len(words)
    while i < n:
        w, ln, ph = words[i]
        if ph or _is_quoted(w) or w not in _ARITY:
            i += 1
            continue
        kw = w.upper()
        arity = _ARITY[kw]
        args: List[str] = []
        surplus: List[str] = []
        j = i + 1
        if arity == -1:  # MATRIX_DIM: all words up to the next keyword/place
            while j < n:
                w2, _, ph2 = words[j]
                if ph2 or (not _is_quoted(w2) and w2 in _ARITY):
                    break
                args.append(w2)
                j += 1
            if len(args) == 0 or len(args) > 3:
                errors.append(
                    (f"MATRIX_DIM has {len(args)} of its 1 to 3 arguments", ln)
                )
        else:
            while j < n and len(args) < arity:
                w2, _, ph2 = words[j]
                if ph2 or (not _is_quoted(w2) and w2 in _ARITY):
                    break
                args.append(w2)
                j += 1
            if kw in _SURPLUS_KINDS:
                while j < n:
                    w2, _, ph2 = words[j]
                    if ph2 or (not _is_quoted(w2) and w2 in _ARITY):
                        break
                    if _is_hex_like(w2):
                        surplus.append(w2)
                        j += 1
                    else:
                        break
            k = len(args) + len(surplus)
            if k != arity:
                errors.append((f"{kw} has {k} of its {arity} arguments", ln))
        items.append((kw, args, surplus, ln))
        i = j
    return items


def _kw(items: List[Tuple[str, List[str], List[str], int]], key: str):
    for kw, args, surplus, ln in items:
        if kw == key:
            return (args, surplus, ln)
    return (None, None, None)


# ---------------------------------------------------------------------------
# Sizes (CTX *sizes*, E3S-03 / E3S-19 / E3S-23).
# ---------------------------------------------------------------------------


def _tag_sizes(
    items: List[Tuple[str, List[str], List[str], int]],
    element_size: Optional[int],
    kind: Optional[str],
    span: Optional[int],
):
    """Return ``(agree, smallest, largest, no_number)``."""
    byte_sizes: List[int] = []
    counts: List[int] = []
    no_number = False
    for kw, args, surplus, ln in items:
        if kw in ("DATA_SIZE", "LENGTH"):
            if len(args) != 1 or surplus:
                no_number = True
                continue
            value = _number_word(args[0])
            if value is None:
                no_number = True
            else:
                byte_sizes.append(value)
        elif kw in ("NUMBER", "ARRAY_SIZE"):
            if len(args) != 1 or surplus:
                no_number = True
                continue
            value = _number_word(args[0])
            if value is None:
                no_number = True
            else:
                counts.append(value)
        elif kw == "MATRIX_DIM":
            if not args or surplus or len(args) > 3:
                no_number = True
                continue
            product = 1
            for w in args:
                value = _number_word(w)
                if value is None:
                    no_number = True
                    break
                product *= value
            if not no_number:
                counts.append(product)

    has_byte = bool(byte_sizes)
    has_count = bool(counts)
    if has_byte and not has_count and not no_number:
        counts.append(1)

    pairs: List[Tuple[int, int]] = []
    if len(byte_sizes) >= 2:
        for i in range(1, len(byte_sizes)):
            pairs.append((byte_sizes[0], byte_sizes[i]))
    if len(counts) >= 2 and kind not in _KIND_FAMILY:
        for i in range(1, len(counts)):
            pairs.append((counts[0], counts[i]))
    if element_size is not None and byte_sizes and counts and kind not in _KIND_FAMILY:
        for c in counts:
            pairs.append((c * element_size, byte_sizes[0]))
    if kind in _KIND_FAMILY and span is not None and byte_sizes:
        pairs.append((span, byte_sizes[0]))

    agree = True
    smallest: Optional[int] = None
    largest: Optional[int] = None
    for a, b in pairs:
        if a != b:
            agree = False
        if smallest is None or min(a, b) < smallest:
            smallest = min(a, b)
        if largest is None or max(a, b) > largest:
            largest = max(a, b)
    if not pairs:
        smallest = largest = None
    return agree, smallest, largest, no_number


# ---------------------------------------------------------------------------
# Length inference.
# ---------------------------------------------------------------------------


def _infer_measurement_length(
    items: List[Tuple[str, List[str], List[str], int]],
    datatype: Optional[str],
) -> Tuple[Optional[int], bool]:
    """Return ``(length, no_number)``. The caller applies the agreement gate."""
    no_number = False
    data_size = None
    length_word = None
    array_size = None
    matrix_product = 1
    has_matrix = False
    for kw, args, surplus, ln in items:
        if surplus:
            no_number = True
        if kw == "DATA_SIZE" and len(args) == 1:
            data_size = _number_word(args[0])
            if data_size is None:
                no_number = True
        elif kw == "LENGTH" and len(args) == 1:
            length_word = _number_word(args[0])
            if length_word is None:
                no_number = True
        elif kw == "ARRAY_SIZE" and len(args) == 1:
            array_size = _number_word(args[0])
            if array_size is None:
                no_number = True
        elif kw == "MATRIX_DIM":
            has_matrix = True
            if not args or len(args) > 3:
                no_number = True
            else:
                product = 1
                for w in args:
                    value = _number_word(w)
                    if value is None:
                        no_number = True
                        break
                    product *= value
                matrix_product = product
    if length_word is not None or data_size is not None:
        value = length_word if length_word is not None else data_size
        return value, no_number
    size = _DATATYPE_SIZES.get(datatype or "")
    if array_size is not None and size is not None:
        return size * array_size, no_number
    if size is not None:
        return size * matrix_product, no_number
    return None, no_number


def _infer_characteristic_length(
    items: List[Tuple[str, List[str], List[str], int]],
    kind: Optional[str],
    deposit: Optional[str],
    layouts: dict,
) -> Tuple[Optional[int], bool]:
    no_number = False
    length_word = None
    data_size = None
    matrix_product = 1
    has_matrix = False
    number = None
    for kw, args, surplus, ln in items:
        if surplus:
            no_number = True
        if kw == "LENGTH" and len(args) == 1:
            length_word = _number_word(args[0])
            if length_word is None:
                no_number = True
        elif kw == "DATA_SIZE" and len(args) == 1:
            data_size = _number_word(args[0])
            if data_size is None:
                no_number = True
        elif kw == "NUMBER" and len(args) == 1:
            number = _number_word(args[0])
            if number is None:
                no_number = True
        elif kw == "MATRIX_DIM":
            has_matrix = True
            if not args or len(args) > 3:
                no_number = True
            else:
                product = 1
                for w in args:
                    value = _number_word(w)
                    if value is None:
                        no_number = True
                        break
                    product *= value
                matrix_product = product
    if length_word is not None or data_size is not None:
        return (length_word if length_word is not None else data_size), no_number
    if kind == "ASCII":
        if number is not None:
            return number, no_number
        if has_matrix and not no_number:
            return matrix_product, no_number
        return None, no_number
    element_size = _characteristic_element_size(kind, deposit, layouts)
    if element_size is None:
        return None, no_number
    if kind == "VAL_BLK":
        if has_matrix and not no_number:
            return element_size * matrix_product, no_number
        if number is not None and not has_matrix:
            return element_size * number, no_number
        return None, no_number
    # VALUE (and anything else scalar): element size (x MATRIX_DIM when present)
    if has_matrix and not no_number and matrix_product > 1:
        return element_size * matrix_product, no_number
    return element_size, no_number


def _characteristic_element_size(kind, deposit, layouts) -> Optional[int]:
    d = (deposit or "").upper()
    size = _deposit_size(d)
    if size is None and kind == "VALUE":
        meta = layouts.get(deposit or "")
        if meta and meta.get("decode_type"):
            size = _DATATYPE_SIZES.get(meta["decode_type"])
    if size is None and kind in ("VAL_BLK", "ASCII", "VALUE"):
        meta = layouts.get(deposit or "")
        if meta and meta.get("decode_type"):
            size = _DATATYPE_SIZES.get(meta["decode_type"])
    return size


# ---------------------------------------------------------------------------
# Tag reader.
# ---------------------------------------------------------------------------


def _read_tags(
    sections: List[dict],
    layouts: dict,
    errors: List[Tuple[str, Optional[int]]],
) -> List[dict]:
    tags: List[dict] = []

    def _module_byte_order(section: dict) -> Optional[str]:
        for child in section.get("children", []):
            if child["name"] == "MOD_COMMON":
                return _byte_order_of_lines(child.get("lines", []))
        return None

    def _walk(secs: List[dict], module_byte_order: Optional[str]) -> None:
        for section in secs:
            mb = module_byte_order
            if section["name"] == "MODULE":
                mb = _module_byte_order(section) or module_byte_order
            if section["name"] in ("MEASUREMENT", "CHARACTERISTIC"):
                tag = _read_tag(section, layouts, mb, errors)
                if tag is not None:
                    tags.append(tag)
            if section.get("children"):
                _walk(section["children"], mb)

    _walk(sections, None)
    return tags


def _read_tag(section, layouts, module_byte_order, errors) -> dict:
    sname = section["name"]
    words = _section_words(section)
    name, long_id, header, rest = _tag_header(sname, words)
    start_line = section["start_line"]

    # Quoted name word holding a non-printable character (R-A2L-READ.4/6).
    if words and _is_quoted(words[0][0]):
        for ch in _unquote(words[0][0]):
            if not (0x21 <= ord(ch) <= 0x7E):
                errors.append(
                    ("unexpected character U+" + f"{ord(ch):04X}", words[0][1])
                )
                break

    # Short-header error (R-A2L-READ.28).
    expect = _HEADER_WORDS[sname]
    if 0 < len(header) < expect:
        errors.append(
            (
                f"{sname} {_echo_word(name)} has {len(header)} of its "
                f"{expect} header words",
                start_line,
            )
        )

    # Not-closed (R-A2L-READ.12 / .67): no tag, one error.
    if section.get("end_line") is None:
        errors.append(
            (f"{sname} {_echo_word(name)} is not closed", start_line)
        )
        return None

    items = _keyword_items(words, rest, errors)

    datatype = None
    conversion = None
    kind = None
    deposit = None
    record_layout_name = None
    header_address = None

    if sname == "MEASUREMENT":
        datatype = header[0] if len(header) >= 1 else None
        conversion = header[1] if len(header) >= 2 else None
    else:
        if len(header) == 7:
            kind = _unquote(header[0])
            header_address = _number_word(header[1])
            deposit = _unquote(header[2])
            record_layout_name = deposit
            conversion = _unquote(header[4])
        else:
            kind = None
            header_address = None
            deposit = None
            record_layout_name = None
            conversion = None

    # Header address not-a-number (R-A2L-READ.63/2; a full 7-word header).
    if (
        sname == "CHARACTERISTIC"
        and len(header) == 7
        and _number_word(header[1]) is None
    ):
        errors.append(
            (
                f"address {_echo_word(header[1])} is not a number",
                words[rest - len(header) + 1][1],
            )
        )

    # Duplicate keywords (R-A2L-READ.32).
    seen_keywords: dict = {}
    for kw, args, surplus, ln in items:
        if kw in seen_keywords:
            errors.append(
                (
                    f"{kw} is declared twice in {sname} {_echo_word(name)}",
                    ln,
                )
            )
        seen_keywords.setdefault(kw, []).append((args, surplus, ln))

    # Field values.
    address_words: List[Tuple[Optional[int], int]] = []
    address_invalid = sname == "CHARACTERISTIC" and len(header) == 7 and header_address is None
    if sname == "CHARACTERISTIC" and header_address is not None:
        address_words.append((header_address, start_line))

    byte_order_arg = None
    byte_order_line = None
    byte_order_invalid = False
    bit_mask = None
    matrix_dim = None
    display_identifier = None

    for kw, args, surplus, ln in items:
        if kw == "ECU_ADDRESS":
            if len(args) == 1 and not surplus:
                value = _number_word(args[0])
                if value is None:
                    address_invalid = True
                    errors.append(
                        (f"ECU_ADDRESS {_echo_word(args[0])} is not a number", ln)
                    )
                else:
                    address_words.append((value, ln))
            else:
                address_invalid = True
        elif kw in ("DATA_SIZE", "LENGTH"):
            if len(args) == 1 and not surplus and _number_word(args[0]) is None:
                errors.append(
                    (f"{kw} {_echo_word(args[0])} is not a number", ln)
                )
        elif kw == "BYTE_ORDER":
            if len(args) == 1 and not surplus:
                byte_order_arg = args[0]
                byte_order_line = ln
                if _normalize_byte_order(byte_order_arg) is None:
                    byte_order_invalid = True
                    errors.append(
                        (
                            "BYTE_ORDER " + _echo_word(byte_order_arg)
                            + " is not a byte order",
                            ln,
                        )
                    )
        elif kw == "BIT_MASK":
            if len(args) == 1 and not surplus:
                bit_mask = args[0]
        elif kw == "MATRIX_DIM":
            if args and not surplus and len(args) <= 3:
                product = 1
                ok = True
                for w in args:
                    value = _number_word(w)
                    if value is None:
                        ok = False
                        errors.append(
                            (f"MATRIX_DIM {_echo_word(w)} is not a number", ln)
                        )
                        break
                    product *= value
                if ok:
                    matrix_dim = product
            else:
                for w in args:
                    if _number_word(w) is None and w not in ("",):
                        errors.append(
                            (f"MATRIX_DIM {_echo_word(w)} is not a number", ln)
                        )
        elif kw == "DISPLAY_IDENTIFIER":
            if len(args) == 1 and not surplus:
                display_identifier = args[0]
        elif kw in ("NUMBER", "ARRAY_SIZE"):
            if len(args) == 1 and not surplus and _number_word(args[0]) is None:
                errors.append(
                    (f"{kw} {_echo_word(args[0])} is not a number", ln)
                )
        elif kw == "DATA_TYPE" and len(args) == 1 and not surplus:
            datatype = args[0]
        elif kw == "FUNCTION" and len(args) == 1 and not surplus:
            pass
        elif kw == "COMPU_METHOD" and len(args) == 1 and not surplus:
            conversion = args[0]

    # Effective byte order and its source (E3S-27).
    effective = None
    if byte_order_arg is not None:
        effective = _normalize_byte_order(byte_order_arg)
    else:
        layout_bo = None
        if record_layout_name and record_layout_name in layouts:
            layout_bo = layouts[record_layout_name].get("byte_order")
            if layout_bo is None and layouts[record_layout_name].get("byte_order_source") is not None:
                layout_bo = layouts[record_layout_name].get("byte_order")
        if layout_bo is not None:
            effective = layout_bo
        elif module_byte_order is not None:
            effective = module_byte_order
        else:
            effective = "little"

    # No address for an invalid address word or byte-order source (READ.60).
    no_address = byte_order_invalid or address_invalid

    # BIT_MASK / BYTE_ORDER with fewer args or surplus (R-A2L-READ.60/6).
    for kw in ("BIT_MASK", "BYTE_ORDER"):
        occ = seen_keywords.get(kw, [])
        if len(occ) >= 2:
            distinct = {_unquote(a[0]) for a, s, l in occ if a}
            if len(distinct) > 1 or any(s for a, s, l in occ):
                no_address = True
                if kw == "BIT_MASK":
                    bit_mask = None
        for args, surplus, ln in occ:
            if len(args) != 1 or surplus:
                no_address = True
                if kw == "BIT_MASK":
                    bit_mask = None

    # Address words: disagreement -> no address + .59 (R-A2L-READ.60/1).
    values = [v for v, ln in address_words]
    if len(set(values)) > 1:
        no_address = True
        errors.append(
            (
                f"{sname} {_echo_word(name)} declares the addresses "
                f"0x{min(values):08X} and 0x{max(values):08X}",
                start_line,
            )
        )
    if values and all(v is None for v in values):
        no_address = True

    address = None
    if not no_address and values and values[0] is not None:
        if values[0] <= 0xFFFFFFFFFFFFFFFF:
            address = values[0]
        # above 2^64-1 -> no address, no error (R-A2L-READ.69)

    # Sizes (R-A2L-READ.59 / .61).
    kind_for_sizes = kind if kind in _KIND_FAMILY else None
    element_size = None
    if sname == "MEASUREMENT":
        element_size = _DATATYPE_SIZES.get(datatype or "")
    else:
        element_size = _characteristic_element_size(kind, deposit, layouts)

    # Inline axis counts for the full _KIND_FAMILY (CURVE, MAP, CUBOID,
    # CUBE_4 and CUBE_5) — the span and the length both need it (P13).
    axis_counts = None
    if kind in _KIND_FAMILY:
        axis_counts = _axis_counts(section)

    span = None
    if kind_for_sizes is not None and record_layout_name in layouts:
        layout = layouts[record_layout_name]
        span = _layout_span(layout, axis_counts)
    agree, smallest, largest, no_number_sizes = _tag_sizes(
        items, element_size, kind_for_sizes, span
    )
    if not agree and smallest is not None and largest is not None:
        errors.append(
            (
                f"{sname} {_echo_word(name)} declares the sizes "
                f"{smallest} and {largest}",
                start_line,
            )
        )

    length = None
    if agree and not no_number_sizes:
        if sname == "MEASUREMENT":
            length, _ = _infer_measurement_length(items, datatype)
        elif kind in _KIND_FAMILY:
            length = span
            if length is None:
                length = _standing_length(items)
        else:
            length, _ = _infer_characteristic_length(
                items, kind, deposit, layouts
            )
    bounded = _bounded_length(length)
    if bounded is None and length is not None:
        errors.append(
            (
                f"{sname} {_echo_word(name)} has the length {length}, "
                "outside 1 to 1048576 bytes",
                start_line,
            )
        )

    return {
        "section": sname,
        "name": name,
        "long_identifier": long_id,
        "address": address,
        "datatype": datatype,
        "byte_order": effective,
        "bit_mask": bit_mask,
        "matrix_dim": matrix_dim,
        "kind": kind,
        "deposit": deposit,
        "conversion": conversion,
        "length": bounded,
        "axis_counts": axis_counts,
        "record_layout_name": record_layout_name,
    }


def _standing_length(items: List[Tuple[str, List[str], List[str], int]]) -> Optional[int]:
    """A standing DATA_SIZE/LENGTH keyword of a CURVE/MAP-family tag, else None."""
    for kw, args, surplus, ln in items:
        if kw in ("DATA_SIZE", "LENGTH") and len(args) == 1 and not surplus:
            value = _number_word(args[0])
            if value is not None:
                return value
    return None


# A RECORD_LAYOUT component whose on-disk element count is one, whatever the
# axes (R-A2L-READ.48: the full byte span; CTX *layout span*).
_FIXED_SPAN_COMPONENTS = frozenset(
    ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y", "NO_AXIS_PTS_Z", "NO_RESCALE_X")
)

# The ALIGNMENT_* directive each datatype class reads its start padding from.
_DATATYPE_ALIGN = {
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

_ALIGN_TOKENS = frozenset(_DATATYPE_ALIGN.values())


def _pad_up(offset: int, align: int) -> int:
    """Round ``offset`` up to a multiple of ``align`` (no pad when <= 1)."""
    if align <= 1:
        return offset
    rem = offset % align
    return offset if rem == 0 else offset + (align - rem)


def _declared_alignments(lines: List[str]) -> Optional[dict]:
    """Collect ``ALIGNMENT_* N`` directives, or None on a bad value."""
    declared: dict = {}
    for text in lines or []:
        tokens = text.split()
        if not tokens or tokens[0] not in _ALIGN_TOKENS:
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


def _layout_span(layout: dict, axis_counts: Optional[List[int]]) -> Optional[int]:
    """R-A2L-READ.48: the on-disk byte span of a CURVE/MAP record layout —
    the sum over EVERY component line of (datatype size x element count), each
    component padded up to its datatype's declared alignment; None when any
    component, datatype or needed axis count is unclassifiable. The reader's
    full multi-component span, not the FNC_VALUES-size x axis product."""
    lines = layout.get("lines") or []
    declared = _declared_alignments(lines)
    if declared is None or axis_counts is None:
        return None
    total = 0
    any_component = False
    for text in lines:
        tokens = text.split()
        if not tokens:
            continue
        component = tokens[0]
        if component in _ALIGN_TOKENS:
            continue
        if component == "DIRECT" and len(tokens) == 1:
            continue
        if component in _FIXED_SPAN_COMPONENTS:
            count = 1
        elif component == "AXIS_PTS_X":
            if len(axis_counts) < 1:
                return None
            count = axis_counts[0]
        elif component == "AXIS_PTS_Y":
            if len(axis_counts) < 2:
                return None
            count = axis_counts[1]
        elif component == "AXIS_PTS_Z":
            if len(axis_counts) < 3:
                return None
            count = axis_counts[2]
        elif component == "FNC_VALUES":
            product = 1
            for c in axis_counts:
                product *= c
            count = product
        elif component == "RESERVED":
            if len(tokens) < 4:
                return None
            try:
                count = int(tokens[3])
            except (ValueError, TypeError):
                return None
            if count < 1:
                return None
        else:
            return None
        if len(tokens) < 3:
            return None
        size = _DATATYPE_SIZES.get(tokens[2])
        if size is None:
            return None
        align = declared.get(_DATATYPE_ALIGN.get(tokens[2]), 1)
        total = _pad_up(total, align) + size * count
        any_component = True
        if total > _MAX_BYTES:
            return None
    return total if any_component else None


def _axis_counts(section: dict) -> Optional[List[int]]:
    counts: List[int] = []
    for child in section.get("children", []):
        if child["name"] != "AXIS_DESCR":
            continue
        words = _section_words(child)
        header = [w for w, ln, ph in words if not ph]
        if not header:
            return None
        axis_kind = header[0]
        if axis_kind not in ("STD_AXIS", "FIX_AXIS"):
            return None
        if "AXIS_PTS_REF" in [w.upper() for w in header]:
            return None
        if len(header) < 4:
            return None
        value = _number_word(header[3])
        if value is None or value <= 0:
            return None
        counts.append(value)
    return counts if counts else None


# ---------------------------------------------------------------------------
# Declared spans (INSTANCE / BLOB).
# ---------------------------------------------------------------------------


def _read_spans(sections: List[dict], layouts: dict) -> List[dict]:
    spans: List[dict] = []
    typedefs: dict = {}

    def _collect_typedefs(secs: List[dict]) -> None:
        for sec in secs:
            if sec["name"].startswith("TYPEDEF_"):
                words = _section_words(sec)
                name, _, header, _ = _tag_header(sec["name"], words)
                typedefs[name] = (sec["name"], header, sec)
            _collect_typedefs(sec.get("children", []))

    def _walk(secs: List[dict]) -> None:
        for sec in secs:
            if sec["name"] in ("INSTANCE", "BLOB"):
                spans.append(_read_span(sec, layouts, typedefs))
            _walk(sec.get("children", []))

    _collect_typedefs(sections)
    _walk(sections)
    return spans


def _read_span(section: dict, layouts: dict, typedefs: dict) -> dict:
    sname = section["name"]
    words = _section_words(section)
    name, _, header, rest = _tag_header(sname, words)
    address = None
    if len(header) >= 2 and sname == "INSTANCE":
        address = _number_word(header[1])
    if sname == "BLOB" and len(header) >= 1:
        address = _number_word(header[0])

    items = _keyword_items(words, rest, [])
    matrix_product = 1
    has_matrix = False
    for kw, args, surplus, ln in items:
        if kw == "MATRIX_DIM" and args and not surplus and len(args) <= 3:
            has_matrix = True
            product = 1
            for w in args:
                value = _number_word(w)
                if value is None:
                    product = 1
                    has_matrix = False
                    break
                product *= value
            matrix_product = product

    length = None
    if sname == "BLOB":
        if len(header) >= 2:
            length = _bounded_length(_number_word(header[1]))
    else:
        typedef_name = header[0] if len(header) >= 1 else None
        typedef = typedefs.get(typedef_name)
        if typedef is not None:
            tkind, theader, tsection = typedef
            if tkind == "TYPEDEF_MEASUREMENT":
                dt = theader[0] if theader else None
                size = _DATATYPE_SIZES.get(dt or "")
                if size is not None:
                    tmatrix = _typedef_matrix(tsection)
                    length = _bounded_length(size * tmatrix * matrix_product)
            elif tkind == "TYPEDEF_CHARACTERISTIC":
                tkind2 = theader[0] if theader else None
                tdeposit = theader[1] if len(theader) > 1 else None
                if tdeposit is not None and _number_word(tdeposit) is not None:
                    # ASAP2 1.6 with-address form: theader[1] is the address.
                    tdeposit = theader[2] if len(theader) > 2 else None
                if tkind2 in ("VALUE", "VAL_BLK", "ASCII"):
                    titems = _keyword_items(_section_words(tsection), len(theader), [])
                    tlen, _ = _infer_characteristic_length(
                        titems, tkind2, tdeposit, layouts
                    )
                    if tlen is not None:
                        length = _bounded_length(tlen * matrix_product)
            elif tkind in ("TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"):
                size_word = theader[0] if theader else None
                size = _number_word(size_word or "")
                if size is not None:
                    length = _bounded_length(size * matrix_product)
    return {"name": name, "kind": sname, "address": address, "length": length}


def _typedef_matrix(section: dict) -> int:
    words = _section_words(section)
    _, _, header, rest = _tag_header(section["name"], words)
    items = _keyword_items(words, rest, [])
    product = 1
    for kw, args, surplus, ln in items:
        if kw == "MATRIX_DIM" and args and not surplus and len(args) <= 3:
            p = 1
            for w in args:
                value = _number_word(w)
                if value is None:
                    p = 1
                    break
                p *= value
            product = p
    return product


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def ref_read_a2l(text: str) -> dict:
    """Reference reading of ``text`` (the file decoded as UTF-8, replacement
    for invalid bytes). Returns reader-shaped sections / tags / spans and
    errors as ``(text, line)`` pairs (line ``None`` for file-level errors)."""
    errors: List[Tuple[str, Optional[int]]] = []

    # UTF-8 BOM dropped (R-A2L-READ.5); a UTF-16 BOM is refused by the reader
    # at the byte level and is not an input to this text-level oracle.
    if text.startswith("\ufeff"):
        text = text[1:]

    # Normalize line ends: CRLF -> LF, then lone CR -> LF (CR CR LF = 2 ends).
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # NUL refusal (R-A2L-READ.55).
    if "\x00" in text:
        return {
            "sections": [],
            "tags": [],
            "spans": [],
            "errors": [("File is not UTF-8 text; save it as UTF-8 and load it again.", None)],
        }

    line_items = _ref_lex(text, errors)
    sections = _ref_tree(line_items, errors)
    if not sections and errors and errors[0][0] == "sections nested deeper than 32":
        return {"sections": [], "tags": [], "spans": [], "errors": errors}

    layouts = _ref_record_layouts(sections)
    tags = _read_tags(sections, layouts, errors)
    spans = _read_spans(sections, layouts)

    # Error cap (R-A2L-READ.56): first 100 + a "… <k> more parse errors" line.
    if len(errors) > _ERROR_CAP:
        dropped = len(errors) - _ERROR_CAP
        errors = errors[:_ERROR_CAP] + [(f"\u2026 {dropped} more parse errors", None)]

    return {
        "sections": sections,
        "tags": tags,
        "spans": spans,
        "errors": errors,
    }
