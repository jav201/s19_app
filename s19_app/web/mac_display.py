from __future__ import annotations

from typing import Any, Optional

from s19_app.tui.models import LoadedFile

from .a2l_utils import build_a2l_name_index


def mac_table_rows(loaded: LoadedFile, a2l_data: Optional[dict]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Summary:
        Build MAC record rows with A2L and in-image columns for HTML rendering.

    Args:
        loaded (LoadedFile): MAC-loaded file with ``mac_records``.
        a2l_data (Optional[dict]): Parsed A2L payload for cross-check.

    Returns:
        tuple[list[dict[str, Any]], dict[str, int]]: Row dicts and aggregate counts.

    Data Flow:
        - Mirror TUI MAC list status rules at a high level.
        - Emit one dict per record with string fields safe for templates.

    Dependencies:
        Uses:
            - ``build_a2l_name_index``
    """
    records = loaded.mac_records or []
    a2l_name_index = build_a2l_name_index(a2l_data)
    rows_out: list[dict[str, Any]] = []
    total_valid = 0
    total_invalid = 0
    total_in_a2l = 0
    total_out_of_mem = 0
    total_parse_errors = 0

    for record in records:
        line_no = int(record.get("line_number") or 0)
        name = str(record.get("name") or "").strip()
        address = record.get("address")
        parse_ok = bool(record.get("parse_ok"))
        parse_error = str(record.get("parse_error") or "")
        if not parse_ok:
            total_parse_errors += 1

        in_a2l = False
        a2l_match_text = ""
        if name:
            matches = a2l_name_index.get(name.lower(), [])
            if matches:
                in_a2l = True
                total_in_a2l += 1
                best = matches[0]
                a2l_match_text = f"{best.get('section', '?')}:{best.get('name', name)}"

        memory_checked = False
        in_memory: Optional[bool] = None
        if loaded.file_type in {"s19", "hex"} and isinstance(address, int):
            memory_checked = True
            in_memory = address in loaded.mem_map

        in_mem_text = "n/a"
        if memory_checked:
            in_mem_text = "yes" if in_memory else "no"
            if in_memory is False:
                total_out_of_mem += 1

        if not parse_ok:
            status = "ERR_PARSE"
            is_invalid = True
        elif not in_a2l:
            status = "NOT_IN_A2L"
            is_invalid = True
        elif memory_checked and in_memory is False:
            status = "OUT_OF_IMAGE"
            is_invalid = True
        else:
            status = "OK"
            is_invalid = False

        if is_invalid:
            total_invalid += 1
        else:
            total_valid += 1

        addr_text = f"0x{address:08X}" if isinstance(address, int) else "n/a"
        rows_out.append(
            {
                "name": name or "(invalid)",
                "address": addr_text,
                "in_a2l": "yes" if in_a2l else "no",
                "in_mem": in_mem_text,
                "status": status,
                "line_no": str(line_no),
                "parse_error": parse_error,
                "a2l_match": a2l_match_text,
                "invalid": is_invalid,
            }
        )

    counts = {
        "total": len(records),
        "valid": total_valid,
        "invalid": total_invalid,
        "in_a2l": total_in_a2l,
        "out_of_mem": total_out_of_mem,
        "parse_errors": total_parse_errors,
    }
    return rows_out, counts
