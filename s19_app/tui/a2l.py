from __future__ import annotations

import logging
from pathlib import Path
import time
from typing import Dict, List, Optional

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


def parse_characteristic_header(line: str) -> Optional[dict]:
    """Parse CHARACTERISTIC mandatory line."""
    parts = _split_line_respecting_quotes(line)
    if len(parts) < 7:
        return None
    if parts[0] not in CHARACTERISTIC_KINDS:
        return None
    addr_raw = parts[1]
    try:
        address_inline = int(addr_raw, 0)
    except ValueError:
        address_inline = None
    return {
        "char_type": parts[0],
        "address_inline": address_inline,
        "deposit": parts[2],
        "max_diff": parts[3],
        "conversion": parts[4],
        "lower_limit": parts[5],
        "upper_limit": parts[6],
        "datatype": None,
    }


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


def _infer_length_characteristic(lines: list[str], header: Optional[dict]) -> Optional[int]:
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
    if char_type == "ASCII" and number_ascii is not None:
        return number_ascii
    if el is None:
        return None
    if matrix is not None and matrix > 0:
        return el * matrix
    if char_type == "VAL_BLK":
        return None
    return el


def extract_a2l_tags(sections: list[dict]) -> list[dict]:
    """Extract MEASUREMENT and CHARACTERISTIC tags with ASAP2-oriented fields."""
    tags: list[dict] = []
    memory_segments = extract_memory_segments(sections)
    target_sections = {"CHARACTERISTIC", "MEASUREMENT"}

    def walk(section_list: list[dict]) -> None:
        for section in section_list:
            name = section.get("name", "")
            meta = section.get("meta", "")
            lines = section.get("lines", [])
            if name in target_sections:
                parsed_name, description = parse_begin_meta(meta)
                hdr_line, _ = _first_header_line(name, lines)
                header_meas = (
                    parse_measurement_header(hdr_line) if name == "MEASUREMENT" and hdr_line else None
                )
                header_char = (
                    parse_characteristic_header(hdr_line) if name == "CHARACTERISTIC" and hdr_line else None
                )
                header = header_meas or header_char

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
                }

                if header_meas:
                    tag["datatype"] = header_meas.get("datatype")
                    tag["conversion"] = header_meas.get("conversion")
                    tag["lower_limit"] = header_meas.get("lower_limit")
                    tag["upper_limit"] = header_meas.get("upper_limit")
                    _apply_conversion_source(tag, tag.get("conversion"))
                if header_char:
                    tag["deposit"] = header_char.get("deposit")
                    tag["conversion"] = header_char.get("conversion")
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
                    tag["length"] = _infer_length_characteristic(lines, header_char)

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
    tags = extract_a2l_tags(sections)
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
    }


def _memory_range_in_map(address: int, length: int, mem_map: Dict[int, int]) -> bool:
    """Check if a memory range is in a memory map."""
    for offset in range(length):
        if address + offset not in mem_map:
            return False
    return True


def _tag_schema_and_applicability(tag: dict) -> tuple[bool, bool, str]:
    """Return (schema_ok, memory_check_applicable, reason_if_schema_bad)."""
    virtual = tag.get("virtual") is True
    address = tag.get("address")
    length = tag.get("length")
    if virtual and address is None:
        return True, False, ""
    if address is None or length is None:
        return False, False, "missing address/length"
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
            results.append(
                {
                    **tag,
                    "schema_ok": schema_ok,
                    "memory_checked": False,
                    "in_memory": None,
                    "reason": reason if not schema_ok else "",
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
        results.append(
            {
                **tag,
                "schema_ok": True,
                "memory_checked": True,
                "in_memory": in_mem,
                "reason": "",
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
