from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Optional

from .model import CoverageMetrics, ValidationIssue, ValidationSeverity
from .rules import validate_a2l_structure, validate_mac_records


@dataclass(slots=True)
class ValidationReport:
    issues: list[ValidationIssue]
    coverage: CoverageMetrics


def _build_range_index(
    ranges: list[tuple[int, int]],
) -> tuple[list[int], list[int]]:
    """
    Summary:
        Build a sorted parallel ``(starts, ends)`` index so address membership checks
        can be answered in ``O(log R)`` rather than ``O(R)`` per record.

    Args:
        ranges (list[tuple[int, int]]): Half-open ``(start, end)`` ranges.

    Returns:
        tuple[list[int], list[int]]: Parallel lists sorted by ``start``.

    Data Flow:
        - Sort a shallow copy of ``ranges`` by start address.
        - Split into two aligned lists for binary search.

    Dependencies:
        Used by:
            - ``validate_artifact_consistency``
    """
    if not ranges:
        return ([], [])
    sorted_ranges = sorted(ranges, key=lambda item: item[0])
    starts = [start for start, _ in sorted_ranges]
    ends = [end for _, end in sorted_ranges]
    return starts, ends


def _address_in_ranges(address: int, index: tuple[list[int], list[int]]) -> bool:
    """Binary-search membership test: ``starts[i] <= address < ends[i]``."""
    starts, ends = index
    if not starts:
        return False
    candidate = bisect.bisect_right(starts, address) - 1
    if candidate < 0:
        return False
    return address < ends[candidate]


def _range_in_ranges(
    address: int, length: int, index: tuple[list[int], list[int]]
) -> bool:
    """Binary-search span-containment test preserving the ``length <= 0`` guard."""
    if length <= 0:
        return False
    starts, ends = index
    if not starts:
        return False
    candidate = bisect.bisect_right(starts, address) - 1
    if candidate < 0:
        return False
    return address >= starts[candidate] and (address + length) <= ends[candidate]


def validate_artifact_consistency(
    mac_records: list[dict],
    a2l_tags: list[dict],
    a2l_data: Optional[dict],
    s19_ranges: list[tuple[int, int]],
    overlapped_addresses: Optional[set[int]] = None,
    alias_policy: str = "warn",
) -> ValidationReport:
    """
    Summary:
        Validate internal and cross-artifact consistency across S19, MAC, and A2L datasets.

    Args:
        mac_records (list[dict]): Parsed MAC records.
        a2l_tags (list[dict]): Parsed/enriched A2L tags.
        a2l_data (Optional[dict]): Parsed A2L document payload for structure/reference checks.
        s19_ranges (list[tuple[int, int]]): Loaded S19 contiguous ranges as ``(start, end)``.
        overlapped_addresses (Optional[set[int]]): Addresses written by multiple S19 records.
        alias_policy (str): Duplicate-MAC-address handling mode (``allow``, ``warn``, ``error``).

    Returns:
        ValidationReport: Combined issue list and coverage metrics.

    Data Flow:
        - Run MAC and A2L internal validators.
        - Build name/address indexes and execute pairwise cross checks.
        - Run triple-consistency checks for symbol name/address agreement.
        - Aggregate and return coverage metrics for dashboards and summaries.

    Dependencies:
        Uses:
        - ``validate_mac_records``
        - ``validate_a2l_structure``
        Used by:
        - TUI cross-validation integration points
        - Validation engine tests
    """

    overlap_set = overlapped_addresses or set()
    range_index = _build_range_index(s19_ranges)
    issues: list[ValidationIssue] = []
    issues.extend(validate_mac_records(mac_records, alias_policy=alias_policy))
    if a2l_data is not None:
        issues.extend(validate_a2l_structure(a2l_data, tags=a2l_tags))

    metrics = CoverageMetrics()
    mac_by_name: dict[str, dict] = {}
    for record in mac_records:
        if not record.get("parse_ok"):
            continue
        name = str(record.get("name") or "").strip()
        addr = record.get("address")
        if not isinstance(addr, int):
            continue
        if name:
            mac_by_name[name.lower()] = record
        metrics.mac_total += 1
        if _address_in_ranges(addr, range_index):
            metrics.mac_in_s19 += 1
        else:
            issues.append(
                ValidationIssue(
                    code="CROSS_MAC_S19_OUT_OF_RANGE",
                    severity=ValidationSeverity.ERROR,
                    message=f"MAC symbol '{name or '?'}' address 0x{addr:08X} not present in S19 image.",
                    artifact="cross",
                    symbol=name or None,
                    address=addr,
                    related_artifacts=["mac", "s19"],
                )
            )
        if addr in overlap_set:
            issues.append(
                ValidationIssue(
                    code="CROSS_MAC_S19_OVERLAP_AMBIGUOUS",
                    severity=ValidationSeverity.WARNING,
                    message=f"MAC symbol '{name or '?'}' points to overlapped S19 address 0x{addr:08X}.",
                    artifact="cross",
                    symbol=name or None,
                    address=addr,
                    related_artifacts=["mac", "s19"],
                )
            )

    a2l_by_name: dict[str, dict] = {}
    for tag in a2l_tags:
        name = str(tag.get("name") or "").strip()
        addr = tag.get("address")
        length = tag.get("length")
        if not isinstance(addr, int):
            continue
        if name:
            a2l_by_name[name.lower()] = tag
        metrics.a2l_total += 1
        byte_len = int(length) if isinstance(length, int) else 1
        if _range_in_ranges(addr, max(1, byte_len), range_index):
            metrics.a2l_in_s19 += 1
        else:
            issues.append(
                ValidationIssue(
                    code="CROSS_A2L_S19_OUT_OF_RANGE",
                    severity=ValidationSeverity.ERROR,
                    message=f"A2L symbol '{name or '?'}' range is not fully present in S19 image.",
                    artifact="cross",
                    symbol=name or None,
                    address=addr,
                    related_artifacts=["a2l", "s19"],
                )
            )
        if addr in overlap_set:
            issues.append(
                ValidationIssue(
                    code="CROSS_A2L_S19_OVERLAP_AMBIGUOUS",
                    severity=ValidationSeverity.WARNING,
                    message=f"A2L symbol '{name or '?'}' points to overlapped S19 address 0x{addr:08X}.",
                    artifact="cross",
                    symbol=name or None,
                    address=addr,
                    related_artifacts=["a2l", "s19"],
                )
            )

    all_names = set(a2l_by_name).union(set(mac_by_name))
    for lowered_name in sorted(all_names):
        in_a2l = lowered_name in a2l_by_name
        in_mac = lowered_name in mac_by_name
        if in_a2l and in_mac:
            metrics.a2l_mac_intersection += 1
            a2l_addr = a2l_by_name[lowered_name].get("address")
            mac_addr = mac_by_name[lowered_name].get("address")
            if a2l_addr == mac_addr:
                metrics.a2l_mac_address_matches += 1
            else:
                issues.append(
                    ValidationIssue(
                        code="TRIPLE_NAME_ADDRESS_MISMATCH",
                        severity=ValidationSeverity.ERROR,
                        message=(
                            f"Symbol '{lowered_name}' has address mismatch "
                            f"(A2L=0x{int(a2l_addr):08X}, MAC=0x{int(mac_addr):08X})."
                        ),
                        artifact="cross",
                        symbol=lowered_name,
                        related_artifacts=["a2l", "mac", "s19"],
                    )
                )
        elif in_mac:
            issues.append(
                ValidationIssue(
                    code="CROSS_MAC_ONLY_SYMBOL",
                    severity=ValidationSeverity.WARNING,
                    message=f"MAC symbol '{lowered_name}' missing from A2L.",
                    artifact="cross",
                    symbol=lowered_name,
                    related_artifacts=["mac", "a2l"],
                )
            )
        elif in_a2l:
            issues.append(
                ValidationIssue(
                    code="CROSS_A2L_ONLY_SYMBOL",
                    severity=ValidationSeverity.WARNING,
                    message=f"A2L symbol '{lowered_name}' missing from MAC.",
                    artifact="cross",
                    symbol=lowered_name,
                    related_artifacts=["a2l", "mac"],
                )
            )

    return ValidationReport(issues=issues, coverage=metrics)
