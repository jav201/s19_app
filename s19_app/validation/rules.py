from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .model import ValidationIssue, ValidationSeverity

RECOGNIZED_A2L_BLOCKS = {
    "PROJECT",
    "MODULE",
    "CHARACTERISTIC",
    "MEASUREMENT",
    "GROUP",
    "FUNCTION",
    "MEMORY_SEGMENT",
    "RECORD_LAYOUT",
    "COMPU_METHOD",
    "COMPU_TAB",
    "COMPU_VTAB",
    "TYPEDEF_CHARACTERISTIC",
    "TYPEDEF_MEASUREMENT",
    "AXIS_PTS",
    "IF_DATA",
}

REFERENCE_KEYWORDS = {
    "REF_CHARACTERISTIC",
    "REF_MEASUREMENT",
    "DEF_CHARACTERISTIC",
    "IN_MEASUREMENT",
    "OUT_MEASUREMENT",
}


def validate_mac_records(records: list[dict], alias_policy: str = "warn") -> list[ValidationIssue]:
    """
    Summary:
        Validate parsed MAC records for format integrity and duplicate/alias semantic constraints.

    Args:
        records (list[dict]): Parsed MAC records from ``parse_mac_file``.
        alias_policy (str): Alias behavior for duplicate addresses (``allow``, ``warn``, ``error``).

    Returns:
        list[ValidationIssue]: MAC-domain validation findings.

    Data Flow:
        - Validate required ``name`` and integer ``address`` for parse-valid records.
        - Detect duplicate tag names and duplicate addresses.
        - Map duplicate-address handling to configured alias policy severity.

    Dependencies:
        Used by:
        - Cross-artifact validation engine
        - MAC-focused tests
    """

    issues: list[ValidationIssue] = []
    by_name: dict[str, list[dict]] = defaultdict(list)
    by_address: dict[int, list[dict]] = defaultdict(list)

    for record in records:
        line_number = record.get("line_number")
        if not record.get("parse_ok"):
            issues.append(
                ValidationIssue(
                    code="MAC_PARSE_ERROR",
                    severity=ValidationSeverity.ERROR,
                    message=str(record.get("parse_error") or "parse error"),
                    artifact="mac",
                    line_number=line_number if isinstance(line_number, int) else None,
                )
            )
            continue
        name = str(record.get("name") or "").strip()
        address = record.get("address")
        if not name:
            issues.append(
                ValidationIssue(
                    code="MAC_EMPTY_NAME",
                    severity=ValidationSeverity.ERROR,
                    message="MAC entry has empty tag name.",
                    artifact="mac",
                    line_number=line_number if isinstance(line_number, int) else None,
                )
            )
        if not isinstance(address, int):
            issues.append(
                ValidationIssue(
                    code="MAC_INVALID_ADDRESS",
                    severity=ValidationSeverity.ERROR,
                    message="MAC entry has invalid or missing hexadecimal address.",
                    artifact="mac",
                    symbol=name or None,
                    line_number=line_number if isinstance(line_number, int) else None,
                )
            )
            continue
        by_name[name.lower()].append(record)
        by_address[address].append(record)

    for lowered_name, name_records in by_name.items():
        if len(name_records) <= 1:
            continue
        issues.append(
            ValidationIssue(
                code="MAC_DUPLICATE_NAME",
                severity=ValidationSeverity.ERROR,
                message=f"MAC symbol '{lowered_name}' is defined multiple times.",
                artifact="mac",
                symbol=name_records[0].get("name"),
            )
        )

    alias_severity = {
        "allow": ValidationSeverity.INFO,
        "warn": ValidationSeverity.WARNING,
        "error": ValidationSeverity.ERROR,
    }.get(alias_policy, ValidationSeverity.WARNING)
    for address, address_records in by_address.items():
        if len(address_records) <= 1:
            continue
        names = sorted({str(item.get("name") or "").strip() for item in address_records if item.get("name")})
        issues.append(
            ValidationIssue(
                code="MAC_DUPLICATE_ADDRESS",
                severity=alias_severity,
                message=f"Address 0x{address:08X} is aliased by MAC symbols: {', '.join(names)}.",
                artifact="mac",
                address=address,
                details={"alias_policy": alias_policy},
            )
        )
    return issues


def _iter_sections(sections: list[dict]) -> list[dict]:
    out: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            out.append(node)
            walk(node.get("children") or [])

    walk(sections)
    return out


def validate_a2l_structure(a2l_data: dict, tags: Optional[list[dict]] = None) -> list[ValidationIssue]:
    """
    Summary:
        Validate A2L structure and symbol integrity from parsed section tree and extracted tags.

    Args:
        a2l_data (dict): Parsed A2L payload from ``parse_a2l_file``.
        tags (Optional[list[dict]]): Optional precomputed/enriched tag list.

    Returns:
        list[ValidationIssue]: A2L-domain structural and reference findings.

    Data Flow:
        - Convert parser structural errors into typed issues.
        - Validate section names against recognized block catalog.
        - Check tag address fields and duplicate tag symbols.
        - Resolve GROUP/FUNCTION references to known symbols where possible.

    Dependencies:
        Used by:
        - Cross-artifact validation engine
        - A2L-focused tests
    """

    issues: list[ValidationIssue] = []
    sections = a2l_data.get("sections", []) if isinstance(a2l_data, dict) else []
    parse_errors = a2l_data.get("errors", []) if isinstance(a2l_data, dict) else []
    effective_tags = tags if tags is not None else a2l_data.get("tags", [])

    for err in parse_errors:
        issues.append(
            ValidationIssue(
                code="A2L_STRUCTURE_ERROR",
                severity=ValidationSeverity.ERROR,
                message=str(err),
                artifact="a2l",
            )
        )

    known_symbols: set[str] = set()
    by_name: dict[str, list[dict]] = defaultdict(list)
    for tag in effective_tags or []:
        name = str(tag.get("name") or "").strip()
        if not name:
            continue
        known_symbols.add(name)
        by_name[name.lower()].append(tag)
        address = tag.get("address")
        if address is not None and not isinstance(address, int):
            issues.append(
                ValidationIssue(
                    code="A2L_INVALID_ADDRESS",
                    severity=ValidationSeverity.ERROR,
                    message=f"A2L symbol '{name}' has invalid address field.",
                    artifact="a2l",
                    symbol=name,
                )
            )
    for lowered_name, entries in by_name.items():
        if len(entries) > 1:
            issues.append(
                ValidationIssue(
                    code="A2L_DUPLICATE_SYMBOL",
                    severity=ValidationSeverity.ERROR,
                    message=f"A2L symbol '{lowered_name}' is defined multiple times.",
                    artifact="a2l",
                    symbol=entries[0].get("name"),
                )
            )

    for section in _iter_sections(sections):
        section_name = str(section.get("name") or "").strip().upper()
        if section_name and section_name not in RECOGNIZED_A2L_BLOCKS:
            issues.append(
                ValidationIssue(
                    code="A2L_UNRECOGNIZED_BLOCK",
                    severity=ValidationSeverity.WARNING,
                    message=f"Unrecognized A2L block '{section_name}'.",
                    artifact="a2l",
                    line_number=section.get("start_line") if isinstance(section.get("start_line"), int) else None,
                )
            )
        if section_name not in {"GROUP", "FUNCTION"}:
            continue
        for raw in section.get("lines", []) or []:
            tokens = raw.strip().split()
            if not tokens:
                continue
            keyword = tokens[0].upper()
            if keyword not in REFERENCE_KEYWORDS:
                continue
            for symbol in tokens[1:]:
                if symbol not in known_symbols:
                    issues.append(
                        ValidationIssue(
                            code="A2L_BROKEN_REFERENCE",
                            severity=ValidationSeverity.WARNING,
                            message=f"{section_name} references unknown symbol '{symbol}'.",
                            artifact="a2l",
                            symbol=symbol,
                        )
                    )
    return issues
