from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional

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


MAC_DUPLICATE_ALIAS_CANDIDATE = "alias candidate"
MAC_DUPLICATE_BITFIELD_SHARING = "bitfield sharing"
MAC_DUPLICATE_SEGMENT_AMBIGUITY = "segment ambiguity"
MAC_DUPLICATE_HARD_CONFLICT = "hard conflict"
MAC_DUPLICATE_VALID_UNRESOLVED = "valid unresolved"


@dataclass(slots=True)
class MacDuplicateGroup:
    """
    Summary:
        Hold one duplicate-address MAC record group for downstream classification.

    Args:
        address (int): Shared ECU address for all records in the group.
        records (list[dict[str, Any]]): Parse-valid records participating in the group.
        names (list[str]): Non-empty symbol names collected from group records.
        unique_names (list[str]): Sorted unique symbol names for stable output.
        line_numbers (list[int]): Source line numbers for diagnostics when available.

    Returns:
        None: Dataclass container for duplicate grouping.

    Data Flow:
        - Grouping pass builds one instance per shared address.
        - Classification pass reads stable name/address/line fields.
        - Validation issue emission serializes fields into details metadata.

    Dependencies:
        Used by:
        - ``collect_mac_duplicate_address_groups``
        - ``classify_mac_duplicate_group``
        - ``validate_mac_records``
    """

    address: int
    records: list[dict[str, Any]]
    names: list[str]
    unique_names: list[str]
    line_numbers: list[int]


def collect_mac_duplicate_address_groups(records: list[dict[str, Any]]) -> list[MacDuplicateGroup]:
    """
    Summary:
        Collect parse-valid MAC records into groups that share the same integer address.

    Args:
        records (list[dict[str, Any]]): Parsed MAC records from ``parse_mac_file``.

    Returns:
        list[MacDuplicateGroup]: Duplicate-address groups with stable metadata fields.

    Data Flow:
        - Filter to parse-valid rows with integer ``address``.
        - Bucket records by address.
        - Keep only addresses with more than one record and derive names/line metadata.

    Dependencies:
        Used by:
        - ``validate_mac_records``
    """
    by_address: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if not record.get("parse_ok"):
            continue
        address = record.get("address")
        if not isinstance(address, int):
            continue
        by_address[address].append(record)

    groups: list[MacDuplicateGroup] = []
    for address, address_records in by_address.items():
        if len(address_records) <= 1:
            continue
        names = [str(item.get("name") or "").strip() for item in address_records if str(item.get("name") or "").strip()]
        line_numbers = [
            line_number
            for line_number in (item.get("line_number") for item in address_records)
            if isinstance(line_number, int)
        ]
        groups.append(
            MacDuplicateGroup(
                address=address,
                records=address_records,
                names=names,
                unique_names=sorted(set(names), key=str.lower),
                line_numbers=sorted(set(line_numbers)),
            )
        )
    return groups


def _build_a2l_name_address_index(a2l_tags: Optional[list[dict[str, Any]]]) -> dict[str, set[int]]:
    """
    Summary:
        Build a lowercased A2L symbol-to-address set index for contradiction checks.

    Args:
        a2l_tags (Optional[list[dict[str, Any]]]): A2L tags supplied by cross validation flow.

    Returns:
        dict[str, set[int]]: Mapping of lowercased symbol name to integer address set.

    Data Flow:
        - Skip empty names and non-integer addresses.
        - Normalize names to lowercase.
        - Accumulate all addresses observed per name.

    Dependencies:
        Used by:
        - ``classify_mac_duplicate_group``
    """
    index: dict[str, set[int]] = defaultdict(set)
    for tag in a2l_tags or []:
        name = str(tag.get("name") or "").strip()
        address = tag.get("address")
        if not name or not isinstance(address, int):
            continue
        index[name.lower()].add(address)
    return index


def _looks_like_bitfield_sharing(names: list[str]) -> bool:
    """
    Summary:
        Infer likely bitfield alias intent from symbol naming patterns.

    Args:
        names (list[str]): Unique symbol names from a duplicate-address group.

    Returns:
        bool: True when names strongly suggest packed-bit or flag aliases.

    Data Flow:
        - Normalize names to lowercase.
        - Match simple bit/flag suffix and token patterns.
        - Return True when any name passes a bitfield hint rule.

    Dependencies:
        Used by:
        - ``classify_mac_duplicate_group``
    """
    for name in names:
        lowered = name.lower()
        if any(token in lowered for token in ("bit", "flag", "_b", ".b", "_mask", "mask")):
            return True
    return False


def classify_mac_duplicate_group(
    group: MacDuplicateGroup,
    *,
    a2l_tags: Optional[list[dict[str, Any]]] = None,
    overlapped_addresses: Optional[set[int]] = None,
    duplicate_name_conflicts: Optional[set[str]] = None,
) -> str:
    """
    Summary:
        Classify one duplicate-address MAC group into alias/ambiguity/conflict categories.

    Args:
        group (MacDuplicateGroup): Duplicate-address group to classify.
        a2l_tags (Optional[list[dict[str, Any]]]): A2L tags used for contradiction checks.
        overlapped_addresses (Optional[set[int]]): S19 overlap set used as ambiguity signal.
        duplicate_name_conflicts (Optional[set[str]]): Lowercased names that already conflict.

    Returns:
        str: One of ``alias candidate``, ``bitfield sharing``, ``segment ambiguity``,
        ``hard conflict``, or ``valid unresolved``.

    Data Flow:
        - Escalate to hard conflict when same-name contradictions are already present.
        - Escalate to hard conflict when A2L resolves group names away from group address.
        - Classify overlap-backed duplicates as segment ambiguity.
        - Classify name-hinted packed aliases as bitfield sharing.
        - Default to alias candidate for ambiguous duplicate addresses.

    Dependencies:
        Uses:
        - ``_build_a2l_name_address_index``
        - ``_looks_like_bitfield_sharing``
        Used by:
        - ``validate_mac_records``
    """
    lowered_names = {name.lower() for name in group.unique_names if name}
    if duplicate_name_conflicts and lowered_names.intersection(duplicate_name_conflicts):
        return MAC_DUPLICATE_HARD_CONFLICT

    a2l_index = _build_a2l_name_address_index(a2l_tags)
    if a2l_index:
        contradicting_names = []
        for lowered_name in lowered_names:
            known_addresses = a2l_index.get(lowered_name) or set()
            if known_addresses and group.address not in known_addresses:
                contradicting_names.append(lowered_name)
        if contradicting_names:
            return MAC_DUPLICATE_HARD_CONFLICT

    if overlapped_addresses and group.address in overlapped_addresses:
        return MAC_DUPLICATE_SEGMENT_AMBIGUITY
    if _looks_like_bitfield_sharing(group.unique_names):
        return MAC_DUPLICATE_BITFIELD_SHARING
    if not group.unique_names:
        return MAC_DUPLICATE_VALID_UNRESOLVED
    return MAC_DUPLICATE_ALIAS_CANDIDATE


def classification_to_severity(classification: str, alias_policy: str = "warn") -> ValidationSeverity:
    """
    Summary:
        Map MAC duplicate-address classification labels to report severities.

    Args:
        classification (str): Duplicate classification output from ``classify_mac_duplicate_group``.
        alias_policy (str): Legacy compatibility policy for unresolved alias handling.

    Returns:
        ValidationSeverity: Severity bucket for issue rendering/filtering.

    Data Flow:
        - Promote hard conflicts to errors.
        - Keep ambiguity classes as warnings by default.
        - Allow legacy ``allow`` policy to downgrade non-conflicts to info.
        - Fall back to info for unresolved-valid categories.

    Dependencies:
        Used by:
        - ``validate_mac_records``
    """
    if classification == MAC_DUPLICATE_HARD_CONFLICT:
        return ValidationSeverity.ERROR
    if classification in {
        MAC_DUPLICATE_ALIAS_CANDIDATE,
        MAC_DUPLICATE_BITFIELD_SHARING,
        MAC_DUPLICATE_SEGMENT_AMBIGUITY,
    }:
        if alias_policy == "allow":
            return ValidationSeverity.INFO
        return ValidationSeverity.WARNING
    return ValidationSeverity.INFO


def validate_mac_records(
    records: list[dict],
    alias_policy: str = "warn",
    a2l_tags: Optional[list[dict[str, Any]]] = None,
    overlapped_addresses: Optional[set[int]] = None,
) -> list[ValidationIssue]:
    """
    Summary:
        Validate parsed MAC records for format integrity and duplicate/alias semantic constraints.

    Args:
        records (list[dict]): Parsed MAC records from ``parse_mac_file``.
        alias_policy (str): Legacy alias behavior flag (``allow``, ``warn``, ``error``).
        a2l_tags (Optional[list[dict[str, Any]]]): Optional A2L tags for contradiction checks.
        overlapped_addresses (Optional[set[int]]): Optional overlapped S19 addresses for ambiguity.

    Returns:
        list[ValidationIssue]: MAC-domain validation findings.

    Data Flow:
        - Validate required ``name`` and integer ``address`` for parse-valid records.
        - Detect duplicate symbol-name contradictions.
        - Group duplicate addresses, classify each group, and map classification to severity.

    Dependencies:
        Used by:
        - Cross-artifact validation engine
        - MAC-focused tests
    """

    issues: list[ValidationIssue] = []
    by_name: dict[str, list[dict]] = defaultdict(list)
    duplicate_name_conflicts: set[str] = set()

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

    for lowered_name, name_records in by_name.items():
        if len(name_records) <= 1:
            continue
        duplicate_name_conflicts.add(lowered_name)
        issues.append(
            ValidationIssue(
                code="MAC_DUPLICATE_NAME",
                severity=ValidationSeverity.ERROR,
                message=f"MAC symbol '{lowered_name}' is defined multiple times.",
                artifact="mac",
                symbol=name_records[0].get("name"),
            )
        )

    for group in collect_mac_duplicate_address_groups(records):
        classification = classify_mac_duplicate_group(
            group,
            a2l_tags=a2l_tags,
            overlapped_addresses=overlapped_addresses,
            duplicate_name_conflicts=duplicate_name_conflicts,
        )
        duplicate_severity = classification_to_severity(classification, alias_policy=alias_policy)
        names_display = ", ".join(group.unique_names) if group.unique_names else "(unknown symbols)"
        issues.append(
            ValidationIssue(
                code="MAC_DUPLICATE_ADDRESS",
                severity=duplicate_severity,
                message=(
                    f"Address 0x{group.address:08X} has duplicate MAC symbols "
                    f"({classification}): {names_display}."
                ),
                artifact="mac",
                address=group.address,
                details={
                    "classification": classification,
                    "group_size": str(len(group.records)),
                    "group_names": ",".join(group.unique_names),
                    "group_lines": ",".join(str(value) for value in group.line_numbers),
                    "resolution_state": (
                        "resolved" if duplicate_severity != ValidationSeverity.INFO else "unresolved"
                    ),
                    "alias_policy": alias_policy,
                },
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
