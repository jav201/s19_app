from __future__ import annotations

import logging
from typing import Callable, Optional

from ...validation import (
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
    validate_artifact_consistency,
    validate_mac_records,
)
from ...validation.model import CoverageMetrics
from ..a2l_validate import validate_a2l_internal_issues
from ..models import LoadedFile

logger = logging.getLogger(__name__)


def build_validation_report(
    records: list[dict],
    primary_file: Optional[LoadedFile],
    a2l_data: Optional[dict],
    a2l_enriched_tags: Optional[list[dict]],
    dedupe_issues: Callable[[list[ValidationIssue]], list[ValidationIssue]],
    overlapped_addresses: Optional[set[int]] = None,
) -> tuple[Optional[ValidationReport], list[ValidationIssue], Optional[str]]:
    """
    Summary:
        Compose validation issues for MAC-only and cross-artifact sessions in one entry point.

    Args:
        records (list[dict]): Parsed MAC records to validate.
        primary_file (Optional[LoadedFile]): Active S19/HEX file for cross-artifact checks.
        a2l_data (Optional[dict]): Parsed A2L payload used for structural validation.
        a2l_enriched_tags (Optional[list[dict]]): Optional enriched A2L tags for cross checks.
        dedupe_issues (Callable[[list[ValidationIssue]], list[ValidationIssue]]): Stable dedupe hook.
        overlapped_addresses (Optional[set[int]]): S19 overlap set for ambiguity diagnostics.

    Returns:
        tuple[Optional[ValidationReport], list[ValidationIssue], Optional[str]]: Validation report
        object, de-duplicated issue list, and optional coverage text (available for primary-backed
        cross validation only).

    Data Flow:
        - Resolve effective A2L tags from enriched input or raw A2L parse output.
        - For MAC-only sessions, run MAC validator directly and skip coverage.
        - For primary-backed sessions, run full cross-artifact validator and optional A2L internals.
        - De-duplicate and return the finalized issue list with optional coverage text.

    Dependencies:
        Uses:
            - ``validate_mac_records``
            - ``validate_artifact_consistency``
            - ``validate_a2l_internal_issues``
        Used by:
            - ``S19TuiApp._compute_mac_view_payload``
            - TUI service tests
    """
    if a2l_enriched_tags is None:
        tags_for_validation = (a2l_data or {}).get("tags", [])
    else:
        tags_for_validation = a2l_enriched_tags
    overlap_set = overlapped_addresses or set()
    if primary_file is None:
        mac_only_issues = validate_mac_records(
            records,
            a2l_tags=tags_for_validation,
            overlapped_addresses=overlap_set,
        )
        report = ValidationReport(
            issues=dedupe_issues(mac_only_issues),
            coverage=CoverageMetrics(),
        )
        return report, list(report.issues), None
    report = validate_artifact_consistency(
        mac_records=records,
        a2l_tags=tags_for_validation,
        a2l_data=a2l_data,
        s19_ranges=primary_file.ranges,
        overlapped_addresses=overlap_set,
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
    if not any(issue.severity == ValidationSeverity.ERROR for issue in issues):
        logger.debug("Validation report produced with no hard errors.")
    coverage_line = (
        f"Coverage MAC->S19={report.coverage.mac_in_s19_pct():.1f}%  "
        f"A2L->S19={report.coverage.a2l_in_s19_pct():.1f}%  "
        f"A2L<->MAC={report.coverage.a2l_mac_match_pct():.1f}%"
    )
    return report, issues, coverage_line
