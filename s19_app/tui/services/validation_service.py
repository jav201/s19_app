from __future__ import annotations

from typing import Callable, Optional

from ...validation import ValidationIssue, ValidationReport, validate_artifact_consistency
from ..a2l_validate import validate_a2l_internal_issues
from ..models import LoadedFile


def build_validation_report(
    records: list[dict],
    primary_file: Optional[LoadedFile],
    a2l_data: Optional[dict],
    a2l_enriched_tags: list[dict],
    dedupe_issues: Callable[[list[ValidationIssue]], list[ValidationIssue]],
    overlapped_addresses: Optional[set[int]] = None,
) -> tuple[Optional[ValidationReport], list[ValidationIssue], Optional[str]]:
    """
    Compose cross-artifact validation report, de-duplicated issue list, and coverage string.
    """
    if primary_file is None:
        return None, [], None
    tags_for_validation = a2l_enriched_tags or (a2l_data or {}).get("tags", [])
    report = validate_artifact_consistency(
        mac_records=records,
        a2l_tags=tags_for_validation,
        a2l_data=a2l_data,
        s19_ranges=primary_file.ranges,
        overlapped_addresses=overlapped_addresses or set(),
    )
    extra_a2l_issues = (
        validate_a2l_internal_issues(
            a2l_data or {"sections": [], "errors": [], "tags": []},
            tag_checks=a2l_enriched_tags or [],
        )
        if a2l_data
        else []
    )
    report.issues = dedupe_issues(report.issues + extra_a2l_issues)
    issues = list(report.issues)
    coverage_line = (
        f"Coverage MAC->S19={report.coverage.mac_in_s19_pct():.1f}%  "
        f"A2L->S19={report.coverage.a2l_in_s19_pct():.1f}%  "
        f"A2L<->MAC={report.coverage.a2l_mac_match_pct():.1f}%"
    )
    return report, issues, coverage_line
