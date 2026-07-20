from __future__ import annotations

import logging
import math
from pathlib import Path
import struct
import time
from typing import Any, Dict, List, Optional
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


def build_section_tree(path: Path) -> tuple[list[dict], list[str]]:
    """
    Summary:
        Parse an A2L file into nested ``/begin``/``/end`` sections while collecting structural errors.

    Args:
        path (Path): File path to A2L text input (UTF-8 with replacement for invalid bytes).

    Returns:
        tuple[list[dict], list[str]]: Section tree list and parser error messages.

    Raises:
        OSError: Re-raised for read errors other than missing file.

    Data Flow:
        - Stream file line-by-line and detect ``/begin`` and ``/end`` markers.
        - Push/pop section nodes on a stack to preserve hierarchy.
        - Attach raw non-marker lines to current open section.
        - Record structural mismatches and unclosed blocks as soft errors.

    Dependencies:
        Uses:
            - ``Path.open``
            - parser stack state in local lists
        Used by:
            - ``parse_a2l_file``
    """
    sections: list[dict] = []
    stack: list[dict] = []
    errors: list[str] = []
    line_count = 0
    begin_count = 0
    end_count = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw in enumerate(handle, 1):
                line_count += 1
                line = raw.rstrip()
                stripped = line.strip()
                if stripped.lower().startswith("/begin"):
                    begin_count += 1
                    parts = stripped.split(maxsplit=2)
                    section_name = parts[1] if len(parts) > 1 else "UNKNOWN"
                    section_meta = parts[2] if len(parts) > 2 else ""
                    entry = {
                        "name": section_name,
                        "meta": section_meta,
                        "start_line": line_number,
                        "lines": [],
                        "children": [],
                    }
                    if stack:
                        stack[-1]["children"].append(entry)
                    else:
                        sections.append(entry)
                    stack.append(entry)
                    continue
                if stripped.lower().startswith("/end"):
                    end_count += 1
                    if stack:
                        stack[-1]["end_line"] = line_number
                        stack.pop()
                    else:
                        errors.append(f"Line {line_number}: /end without /begin")
                    continue
                if stack:
                    stack[-1]["lines"].append(line)
    except FileNotFoundError:
        errors.append("File not found.")
        logger.warning("A2L section parse failed: path=%s reason=file_not_found", path)
    except OSError:
        logger.exception("A2L section parse failed: path=%s reason=os_error", path)
        raise

    if stack:
        errors.append("Unclosed /begin sections detected.")
    logger.info(
        "A2L section tree built: path=%s lines=%d begins=%d ends=%d root_sections=%d errors=%d",
        path,
        line_count,
        begin_count,
        end_count,
        len(sections),
        len(errors),
    )
    if errors:
        logger.warning("A2L section tree has structural errors: path=%s sample=%s", path, "; ".join(errors[:3]))

    return sections, errors


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
    """Return first identifier or quoted string, and remainder."""
    meta = meta.strip()
    if not meta:
        return "", ""
    if meta[0] == '"':
        end = 1
        while end < len(meta):
            if meta[end] == '"' and meta[end - 1] != "\\":
                return meta[1:end], meta[end + 1 :].lstrip()
            end += 1
        return meta[1:], ""
    parts = meta.split(maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""


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
    line = line.strip()
    if not line:
        return []
    tokens: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        if line[i] == '"':
            j = i + 1
            while j < n:
                if line[j] == '"' and line[j - 1] != "\\":
                    break
                j += 1
            tokens.append(line[i + 1 : j])
            i = j + 1
            continue
        j = i
        while j < n and not line[j].isspace():
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
            if c == '"' and text[i - 1] != "\\":
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = i + 2 if i + 1 < n else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != _A2L_LINE_SENTINEL:
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
    body = _A2L_LINE_SENTINEL.join(lines)
    return _split_line_respecting_quotes(_strip_a2l_comments(body))


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
    """Parse MEASUREMENT mandatory line: datatype conversion res acc low high."""
    parts = _split_line_respecting_quotes(line)
    if len(parts) < 6:
        return None
    if parts[0] in MEASUREMENT_BODY_KEYWORDS:
        return None
    return {
        "datatype": parts[0],
        "conversion": parts[1],
        "resolution": parts[2],
        "accuracy": parts[3],
        "lower_limit": parts[4],
        "upper_limit": parts[5],
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
        tokens follow it — never raises ``IndexError``.

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
        - Slice 7 params from the anchor; ``None`` if the slice is short.
        - Parse the address via ``int(x, 0)``; ``ValueError`` → ``None`` address.

    Dependencies:
        Uses:
            - ``CHARACTERISTIC_KINDS``
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
        return None
    params = tokens[anchor : anchor + 7]
    if len(params) < 7:
        return None
    try:
        address_inline: Optional[int] = int(params[1], 0)
    except ValueError:
        address_inline = None
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
        when no kind token / fewer than 7 params.

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


def _first_header_line(
    section_name: str, lines: list[str]
) -> tuple[Optional[str], list[str]]:
    """Return first line that looks like a MEASUREMENT/CHAR header, and all lines."""
    for line in lines:
        if not line.strip():
            continue
        if section_name == "MEASUREMENT" and parse_measurement_header(line):
            return line, lines
        if section_name == "CHARACTERISTIC" and parse_characteristic_header(line):
            return line, lines
    return None, lines


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
        method = {
            "name": method_name,
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


def extract_memory_segments(sections: list[dict]) -> list[dict]:
    """Parse MEMORY_SEGMENT blocks (CODE/DATA FLASH/RAM ROM, base, size)."""
    out: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for sec in nodes:
            if sec.get("name") == "MEMORY_SEGMENT":
                first = ""
                for line in sec.get("lines") or []:
                    if line.strip():
                        first = line.strip()
                        break
                parts = first.split()
                entry: dict = {
                    "block_name": parse_begin_meta(sec.get("meta", "") or "")[0],
                    "raw_first_line": first,
                    "usage": None,
                    "kind": None,
                    "base": None,
                    "size": None,
                }
                if len(parts) >= 5:
                    entry["usage"] = parts[0]
                    entry["kind"] = parts[1]
                    try:
                        entry["base"] = int(parts[3], 0)
                        entry["size"] = int(parts[4], 0)
                    except ValueError:
                        pass
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
    data_size = None
    matrix = 1
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "DATA_SIZE":
            try:
                data_size = int(parts[1], 0)
            except ValueError:
                pass
        if len(parts) >= 2 and parts[0] == "MATRIX_DIM":
            try:
                matrix = int(parts[1], 0)
            except ValueError:
                pass
    if data_size is not None:
        return data_size * matrix if matrix != 1 else data_size
    dt = (header or {}).get("datatype")
    if dt and dt in DATATYPE_SIZES:
        return DATATYPE_SIZES[dt] * matrix
    return None


def _infer_length_characteristic(
    lines: list[str],
    header: Optional[dict],
    record_layouts_by_name: Optional[dict[str, dict]] = None,
) -> Optional[int]:
    explicit = None
    matrix = None
    number_ascii = None
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "LENGTH":
            try:
                explicit = int(parts[1], 0)
            except ValueError:
                pass
        if len(parts) >= 2 and parts[0] == "MATRIX_DIM":
            try:
                matrix = int(parts[1], 0)
            except ValueError:
                pass
        if len(parts) >= 2 and parts[0] == "NUMBER":
            try:
                number_ascii = int(parts[1], 0)
            except ValueError:
                pass
    if explicit is not None:
        return explicit
    h = header or {}
    deposit = str(h.get("deposit") or "")
    char_type = h.get("char_type")
    el = sizeof_from_deposit(deposit)
    if el is None and char_type == "VALUE" and record_layouts_by_name:
        # Scalar VALUE only: the deposit name carries no size hint (e.g. a
        # project-named layout like ``RL_U8``), so resolve the RECORD_LAYOUT
        # and take its element datatype size (ASAM MCD-2 MC — a scalar's size
        # IS its element size). Restricted to VALUE on purpose: a CURVE/MAP is
        # an array over its axes, so the element size would UNDER-report the
        # real span and make the byte-range memory check falsely pass on too
        # few bytes. Those stay length=None (honest grey) unless a MATRIX_DIM
        # or a name-encoded deposit already sized them above.
        meta = _resolve_record_layout(deposit, record_layouts_by_name)
        if meta and meta.get("decode_type"):
            el = DATATYPE_SIZES.get(meta["decode_type"])
    if char_type == "ASCII" and number_ascii is not None:
        return number_ascii
    if el is None:
        return None
    if matrix is not None and matrix > 0:
        return el * matrix
    if char_type == "VAL_BLK":
        return None
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
    element_count = 1
    if tokens:
        try:
            numeric = [int(tok, 0) for tok in tokens if tok.replace("-", "").isdigit()]
            if numeric:
                element_count = max(1, numeric[0])
        except ValueError:
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
        None: An unrecognised line (incl. an unmodeled span-affecting directive
            like ``ALIGNMENT_*``), an unknown datatype, a truncated component, an
            absent needed axis count, an empty contribution, or an over-cap total
            all degrade to ``None`` (never a wrong-but-non-None length → no
            false-green from an under-reported span).

    Data Flow:
        - Iterate ``layout["lines"]``; ONLY a genuinely empty/whitespace line is
          skipped. Every other non-empty line must classify as a summable
          component or force ``None`` — a span-affecting directive we do not model
          (``ALIGNMENT_*`` padding, ``AXIS_RESCALE_X``, ``RESERVED``, a standalone
          comment) must never be silently skipped, or the span under-reports.
        - Map token[0] to an element count via the §2.5 taxonomy keyed on
          ``axis_counts`` (NO_AXIS_PTS/NO_RESCALE → 1; AXIS_PTS_X/Y/Z → the axis
          count; FNC_VALUES → ``math.prod(axis_counts)``); resolve token[2] size
          via ``DATATYPE_SIZES.get``.
        - Accumulate ``size × count``; bail to ``None`` on any unrecognised line,
          truncated component, unknown datatype, missing axis count, or over-cap
          total.

    Dependencies:
        Uses:
            - ``DATATYPE_SIZES``
            - ``MAX_A2L_DECODE_BYTES``
            - ``math.prod``
        Used by:
            - ``extract_a2l_tags`` post-axis-walk length pass

    Example:
        >>> _record_layout_full_span(
        ...     {"lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE", "FNC_VALUES 3 SWORD"]},
        ...     [8],
        ... )
        25
    """
    total = 0
    contributed = False
    for line in layout.get("lines") or []:
        tokens = line.split()
        if not tokens:
            continue
        component = tokens[0]
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
        else:
            # Any non-empty line that is not a summable component forces
            # full-span-or-None: an ALIGNMENT_* padding directive (2 tokens, would
            # add inter-component padding we do not model), an unmodeled component
            # (AXIS_RESCALE_X / RESERVED), or a standalone comment. Skipping it
            # would UNDER-REPORT the true span → a false-green.
            return None
        if len(tokens) < 3:
            return None  # recognised component missing its datatype token
        size = DATATYPE_SIZES.get(tokens[2])
        if size is None:
            return None
        total += size * element_count
        contributed = True
        if total > MAX_A2L_DECODE_BYTES:
            return None
    if not contributed:
        return None
    return total


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


def _apply_compu_method(raw_value: Any, method: Optional[dict], compu_tables_by_name: dict[str, dict]) -> tuple[Any, str, str]:
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
        coeffs = method.get("coeffs") or []
        padded = [(coeffs[i] if i < len(coeffs) and coeffs[i] is not None else 0.0) for i in range(6)]
        a, b, c, d, e, f = padded
        numerator = (a * (raw_value**2)) + (b * raw_value) + c
        denominator = (d * (raw_value**2)) + (e * raw_value) + f
        if math.isclose(denominator, 0.0):
            return None, "error", "RAT_FUNC denominator is zero"
        return numerator / denominator, "ok", ""
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


def extract_a2l_tags(
    sections: list[dict],
    record_layouts_by_name: Optional[dict[str, dict]] = None,
    compu_methods_by_name: Optional[dict[str, dict]] = None,
) -> list[dict]:
    """Extract MEASUREMENT and CHARACTERISTIC tags with ASAP2-oriented fields."""
    tags: list[dict] = []
    memory_segments = extract_memory_segments(sections)
    target_sections = {"CHARACTERISTIC", "MEASUREMENT"}
    record_layouts_by_name = record_layouts_by_name or {}
    compu_methods_by_name = compu_methods_by_name or {}

    def walk(section_list: list[dict]) -> None:
        for section in section_list:
            name = section.get("name", "")
            meta = section.get("meta", "")
            lines = section.get("lines", [])
            if name in target_sections:
                parsed_name, description = parse_begin_meta(meta)
                if name == "MEASUREMENT":
                    hdr_line, _ = _first_header_line(name, lines)
                    header_meas = parse_measurement_header(hdr_line) if hdr_line else None
                    header_char = None
                else:  # CHARACTERISTIC — assemble a possibly multi-line header.
                    header_meas = None
                    header_char = assemble_characteristic_header(lines)

                tag: dict = {
                    "section": name,
                    "name": parsed_name,
                    "description": description,
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
                    if header_char.get("address_inline") is not None:
                        tag["address"] = header_char["address_inline"]
                    _apply_conversion_source(tag, tag.get("conversion"))

                mdim = None
                for line in lines:
                    stripped = line.strip()
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[0] == "ECU_ADDRESS":
                        try:
                            tag["address"] = int(parts[1], 0)
                        except ValueError:
                            tag["address"] = None
                    if len(parts) >= 2 and parts[0] in {"DATA_SIZE", "LENGTH"}:
                        try:
                            tag["length"] = int(parts[1], 0)
                        except ValueError:
                            tag["length"] = None
                    if len(parts) >= 2 and parts[0] == "LOWER_LIMIT":
                        tag["lower_limit"] = parts[1]
                    if len(parts) >= 2 and parts[0] == "UPPER_LIMIT":
                        tag["upper_limit"] = parts[1]
                    if len(parts) >= 2 and parts[0] == "UNIT":
                        tag["unit"] = parts[1]
                    if len(parts) >= 2 and parts[0] == "BYTE_ORDER":
                        tag["endian"] = parts[1]
                        tag["effective_byte_order"] = _normalize_byte_order(parts[1])
                    if len(parts) >= 2 and parts[0] == "BIT_MASK":
                        tag["bit_org"] = parts[1]
                    if len(parts) >= 2 and parts[0] == "DATA_TYPE":
                        tag["datatype"] = parts[1]
                    if len(parts) >= 2 and parts[0] == "FUNCTION":
                        tag["function_group"] = parts[1]
                    if len(parts) >= 1 and parts[0] == "VIRTUAL":
                        tag["virtual"] = True
                    if len(parts) >= 2 and parts[0] == "COMPU_METHOD":
                        tag["conversion"] = parts[1]
                        tag["compu_method_name"] = parts[1]
                        if parts[1] != "NO_COMPU_METHOD":
                            tag["source"] = "formula"
                    if len(parts) >= 1 and parts[0] == "FORMULA":
                        tag["source"] = "formula"
                    if len(parts) >= 1 and parts[0] == "READ_ONLY":
                        tag["access"] = "read_only"
                    if len(parts) >= 1 and parts[0] == "CALIBRATABLE":
                        tag["access"] = "calibratable"
                    if len(parts) >= 2 and parts[0] == "MATRIX_DIM":
                        try:
                            mdim = int(parts[1], 0)
                            tag["matrix_dim"] = mdim
                        except ValueError:
                            pass
                    if len(parts) >= 2 and parts[0] == "DISPLAY_IDENTIFIER":
                        tail = stripped[len("DISPLAY_IDENTIFIER") :].strip()
                        tag["display_identifier"] = tail
                    if len(parts) >= 2 and parts[0] == "SYMBOL_LINK":
                        toks = _split_line_respecting_quotes(stripped)
                        if len(toks) >= 2:
                            tag["symbol_link"] = toks[1]

                lm = collect_link_maps(section)
                if lm:
                    tag["link_map"] = lm

                if name == "MEASUREMENT" and tag["length"] is None:
                    tag["length"] = _infer_length_measurement(lines, header_meas)
                if name == "CHARACTERISTIC" and tag["length"] is None:
                    tag["length"] = _infer_length_characteristic(
                        lines, header_char, record_layouts_by_name
                    )

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

                if (
                    name == "CHARACTERISTIC"
                    and tag.get("char_type") in ("CURVE", "MAP")
                    and tag.get("length") is None
                ):
                    axis_counts = _inline_axis_counts(tag.get("axis_meta") or [])
                    if axis_counts is not None:
                        layout = record_layouts_by_name.get(
                            str(tag.get("record_layout_name") or "")
                        )
                        if layout:
                            tag["length"] = _record_layout_full_span(layout, axis_counts)

                if not tag.get("effective_byte_order"):
                    layout = record_layouts_by_name.get(str(tag.get("record_layout_name") or ""))
                    if layout:
                        tag["effective_byte_order"] = layout.get("byte_order")
                if not tag.get("effective_byte_order"):
                    tag["effective_byte_order"] = _normalize_byte_order(tag.get("endian"))
                if not tag.get("effective_byte_order"):
                    tag["effective_byte_order"] = "little"

                if not tag.get("compu_method_name"):
                    token = tag.get("conversion")
                    if token and token in compu_methods_by_name:
                        tag["compu_method_name"] = token

                tag["memory_region"] = classify_address(tag.get("address"), memory_segments)
                tags.append(tag)
            if section.get("children"):
                walk(section["children"])

    walk(sections)
    return tags


def parse_a2l_file(path: Path) -> dict:
    """
    Summary:
        Parse an A2L file into section tree, extracted tags, and parse diagnostics.

    Args:
        path (Path): Path to A2L file on disk.

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
    sections, errors = build_section_tree(path)
    tag_started = time.perf_counter()
    record_layouts_by_name = extract_record_layouts(sections)
    compu_methods_by_name = extract_compu_methods(sections)
    compu_tabs_by_name = extract_compu_tables(sections)
    tags = extract_a2l_tags(
        sections,
        record_layouts_by_name=record_layouts_by_name,
        compu_methods_by_name=compu_methods_by_name,
    )
    tag_elapsed = time.perf_counter() - tag_started
    parse_elapsed = time.perf_counter() - parse_started
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
        len(errors),
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
        "errors": errors,
        "tags": tags,
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
        physical_value, conversion_status, conversion_error = _apply_compu_method(raw_value, method, compu_tabs_by_name)
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


def iter_section_lines(sections: List[dict], depth: int = 0) -> List[str]:
    """Depth-first lines for /begin tree (indented)."""
    lines: list[str] = []
    indent = "  " * depth
    for section in sections:
        name = section.get("name", "UNKNOWN")
        meta = section.get("meta", "")
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
    """Render a concise, human-readable A2L summary or errors."""
    if not a2l_data:
        return "No A2L loaded."
    if a2l_data.get("errors"):
        errors = "\n".join(f"- {err}" for err in a2l_data["errors"])
        return f"A2L parse errors:\n{errors}"
    sections = a2l_data.get("sections", [])
    tags = a2l_data.get("tags", [])
    if not sections:
        return "No A2L sections found."
    lines_out = ["A2L Sections:", *iter_section_lines(sections)]
    if tags:
        lines_out.append("")
        lines_out.append("A2L Tags:")
        check_map = {}
        if tag_checks:
            check_map = {(item.get("section"), item.get("name")): item for item in tag_checks}
        truncated = False
        emitted_tag_lines = 0
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
            lines_out.append(
                f"- {tag.get('section')} {tag.get('name')}: {addr_text} len={len_text} mem={reg}{tail}".strip()
            )
            emitted_tag_lines += 1
        if truncated:
            remaining = max(0, len(tags) - max_tag_lines)
            lines_out.append(f"... truncated {remaining} additional tag lines ...")
    return "\n".join(lines_out)


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
