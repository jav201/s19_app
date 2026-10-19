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
        try:
            int(candidate, 0)
            continue  # an address/number token, never a Type identifier
        except ValueError:
            pass
        try:
            int(tokens[idx + 1], 0)
        except (ValueError, IndexError):
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


def extract_memory_segments(sections: list[dict]) -> list[dict]:
    """Parse MEMORY_SEGMENT blocks (CODE/DATA FLASH/RAM ROM, base, size, offset).

    Hardened (batch-95, LLR-137.4): the record line is tokenized with
    :func:`_split_line_respecting_quotes`, and the first line tokenizing into
    >= 5 parts is the record — a quoted multi-word long identifier on its own
    line (the shipped ASAP2 demos) collapses to ONE token and is skipped, so
    quoted blocks yield full rows instead of null base/size. Unquoted blocks
    tokenize exactly as the old ``str.split()`` and parse byte-identically.
    Each entry carries the ``offset`` field (record parts[5]) when declared.
    """
    out: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for sec in nodes:
            if sec.get("name") != "MEMORY_SEGMENT":
                walk(sec.get("children") or [])
                continue
            entry: dict = {
                "block_name": parse_begin_meta(sec.get("meta", "") or "")[0],
                "raw_first_line": "",
                "usage": None,
                "kind": None,
                "base": None,
                "size": None,
                "offset": None,
            }
            for line in sec.get("lines") or []:
                stripped = line.strip()
                if not stripped:
                    continue
                parts = _split_line_respecting_quotes(stripped)
                if len(parts) < 5:
                    continue  # a quoted long-identifier line collapses to 1 token
                entry["raw_first_line"] = stripped
                entry["usage"] = parts[0]
                entry["kind"] = parts[1]
                try:
                    entry["base"] = int(parts[3], 0)
                    entry["size"] = int(parts[4], 0)
                except ValueError:
                    pass
                if len(parts) >= 6:
                    try:
                        entry["offset"] = int(parts[5], 0)
                    except ValueError:
                        entry["offset"] = None
                break
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


#: The float datatypes the physical→raw encode packs directly (no integrality
#: or integer-range limb). ``FLOAT16_IEEE`` is deliberately ABSENT — the
#: shipped decode refuses it too (:func:`_decode_scalar` returns ``None``), so
#: the encode cannot round-trip a direction the decode does not ship.
_FLOAT_ENCODE_DATATYPES = frozenset({"FLOAT32_IEEE", "FLOAT64_IEEE"})


def _invert_rat_func(physical: float, method: dict) -> tuple[Optional[float], str]:
    """Invert one RAT_FUNC COMPU_METHOD (physical → raw), quadratic solve.

    Solves ``physical = (a·x² + b·x + c) / (d·x² + e·x + f)`` for ``x`` —
    i.e. the quadratic ``(a − p·d)x² + (b − p·e)x + (c − p·f) = 0``. Two real
    roots choose by the smallest absolute value (the shipped decode's domain
    is calibration monotonicity; the encode documents one deterministic
    pick). Returns ``(raw, "")`` or ``(None, reason)``.
    """
    coeffs = method.get("coeffs") or []
    padded = [
        (coeffs[i] if i < len(coeffs) and coeffs[i] is not None else 0.0)
        for i in range(6)
    ]
    a, b, c, d, e, f = padded
    quad_a = a - physical * d
    quad_b = b - physical * e
    quad_c = c - physical * f
    if math.isclose(quad_a, 0.0):
        if math.isclose(quad_b, 0.0):
            return None, "RAT_FUNC has no solution for this value"
        return -quad_c / quad_b, ""
    discriminant = quad_b * quad_b - 4.0 * quad_a * quad_c
    if discriminant < 0.0:
        return None, "RAT_FUNC has no real root for this value"
    root = math.sqrt(discriminant)
    first = (-quad_b + root) / (2.0 * quad_a)
    second = (-quad_b - root) / (2.0 * quad_a)
    if abs(second) < abs(first):
        return second, ""
    return first, ""


def _reverse_table_lookup(
    physical: float, table: dict, interpolate: bool
) -> tuple[Optional[float], str]:
    """Invert one COMPU_TAB (physical → raw): exact/nearest, or interpolated.

    ``TAB_NOINTP`` mirrors the shipped decode's :func:`_table_lookup` fallback
    (exact y match, else the x of the nearest y). ``TAB_INTP`` inverse-
    interpolates between the bracketing y's and clamps outside the table's
    y-range to the nearest endpoint's x (the decode clamps the same way).
    Non-numeric y entries are skipped; a table with no numeric y refuses.
    """
    numeric: list[tuple[float, float]] = []
    for raw_x, raw_y in table.get("entries") or []:
        y = _to_float(raw_y)
        if y is not None:
            numeric.append((float(raw_x), y))
    if not numeric:
        return None, "lookup table has no numeric entries"
    numeric.sort(key=lambda item: item[0])
    if not interpolate:
        for raw_x, y in numeric:
            if math.isclose(y, physical, rel_tol=0.0, abs_tol=1e-9):
                return raw_x, ""
        nearest = min(numeric, key=lambda item: abs(item[1] - physical))
        return nearest[0], ""
    numeric.sort(key=lambda item: item[1])
    if physical <= numeric[0][1]:
        return numeric[0][0], ""
    if physical >= numeric[-1][1]:
        return numeric[-1][0], ""
    for left, right in zip(numeric, numeric[1:]):
        lx, ly = left
        rx, ry = right
        if ly <= physical <= ry:
            if math.isclose(ry, ly):
                return lx, ""
            ratio = (physical - ly) / (ry - ly)
            return lx + ratio * (rx - lx), ""
    return None, "value outside interpolation range"


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
        tuple[Optional[float], Optional[str]]: ``(raw, None)`` on success;
        ``(None, reason)`` on refusal — the reason names the limb, exactly as
        the scalar encoder's shipped refusals name them.

    Raises:
        None: every limb is a returned reason.

    Data Flow:
        - ``method is None`` → identity (mirrors the decode's
          ``identity_fallback``); ``IDENTICAL`` → identity.
        - ``LINEAR`` → ``raw = (physical − b) / a``; ``a == 0`` refuses.
        - ``RAT_FUNC`` → :func:`_invert_rat_func`; no real root refuses.
        - ``TAB_NOINTP`` / ``TAB_INTP`` → :func:`_reverse_table_lookup`;
          missing/empty/non-numeric table refuses.
        - ``FORM`` / unknown conversion type on a DEFINED method → REFUSE.

    Dependencies:
        Uses:
            - ``_invert_rat_func`` / ``_reverse_table_lookup``
        Used by:
            - ``encode_physical_to_raw_bytes`` / ``_encode_curve_record_bytes``

    Example:
        >>> _invert_physical_to_raw(110.0, {"conversion_type": "LINEAR", "coeffs_linear": [2.0, 10.0]}, None)
        (50.0, None)
    """
    if method is None:
        return physical, None  # the identity limb (no COMPU_METHOD)
    conversion_type = str(method.get("conversion_type") or "").upper()
    if conversion_type == "IDENTICAL":
        return physical, None
    if conversion_type == "LINEAR":
        coeffs = method.get("coeffs_linear") or []
        lin_a = coeffs[0] if len(coeffs) > 0 and coeffs[0] is not None else 1.0
        lin_b = coeffs[1] if len(coeffs) > 1 and coeffs[1] is not None else 0.0
        if math.isclose(lin_a, 0.0):
            return None, "LINEAR conversion coefficient a is zero"
        return (physical - lin_b) / lin_a, None
    if conversion_type == "RAT_FUNC":
        raw, rat_error = _invert_rat_func(physical, method)
        if raw is None:
            return None, rat_error or "RAT_FUNC inversion failed"
        return raw, None
    if conversion_type in {"TAB_NOINTP", "TAB_INTP"}:
        table = (compu_tabs_by_name or {}).get(
            str(method.get("compu_tab_ref") or "")
        )
        if table is None or not table.get("entries"):
            return None, "lookup table missing or empty"
        raw, tab_error = _reverse_table_lookup(
            physical, table, conversion_type == "TAB_INTP"
        )
        if raw is None:
            return None, tab_error or "table inversion failed"
        return raw, None
    # FORM (the decode's own unsupported limb) and every unknown conversion
    # type on a DEFINED method.
    return None, f"conversion type {conversion_type!r} is not supported"


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
            raw, conversion_error = _invert_physical_to_raw(
                physical, method, compu_tabs_by_name
            )
            if conversion_error is not None:
                return None, conversion_error, []
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
          - ``RAT_FUNC`` → quadratic inversion
            (:func:`_invert_rat_func`); no real root refuses;
          - ``TAB_NOINTP`` / ``TAB_INTP`` → reverse table lookup
            (:func:`_reverse_table_lookup`); missing/empty/non-numeric table
            refuses;
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
    raw, conversion_error = _invert_physical_to_raw(
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
    flags: list[str] = []
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
    # R5 external-axis post-pass: a CURVE/MAP whose AXIS_DESCR references an
    # AXIS_PTS record (COM_AXIS / RES_AXIS / CURVE_AXIS) derives its length
    # from the referenced record's max_axis_points when that reference
    # resolves BY NAME in the completed tag list. This runs AFTER the walk
    # because the referenced AXIS_PTS CHARACTERISTIC may be declared after
    # the referencing tag. Full-span-or-None stands: an unresolvable
    # reference (dangling name, no axis_meta, non-numeric count) keeps
    # length=None — never an invented count.
    for tag in tags:
        if (
            tag.get("section") == "CHARACTERISTIC"
            and tag.get("char_type") in ("CURVE", "MAP")
            and tag.get("length") is None
        ):
            counts = _axis_counts_resolving_external(tag.get("axis_meta") or [], tags)
            if counts is None:
                continue
            layout = record_layouts_by_name.get(str(tag.get("record_layout_name") or ""))
            if layout:
                tag["length"] = _record_layout_full_span(layout, counts)
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
            raw_item, method, compu_tabs_by_name
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
        scalar_text = _format_point_number(scalar) if scalar is not None else "n/a"
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
        lines.append(f"  {'x':>{x_width}}   {'y':>{y_width}}")
        for p, x_cell, y_cell in zip(points, x_cells, y_cells):
            note = f"   ({p['x_note']})" if p.get("x_note") else ""
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
