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


def supplemental_a2l_row_issues(
    tags_for_validation: list[dict],
    collected_issues: list[ValidationIssue],
) -> list[ValidationIssue]:
    """
    Summary:
        Emit one ERROR ``ValidationIssue`` (code ``A2L_TAG_SCHEMA_INCOMPLETE``) per A2L
        tag whose ``schema_ok`` field is exactly ``False`` — the same predicate that
        renders the tag's row red in the A2L table — unless an ERROR-severity ``a2l``
        issue for the same casefolded symbol was already collected (LLR-036.1 /
        LLR-036.2, US-032 red-row-implies-issue).

    Args:
        tags_for_validation (list[dict]): Effective A2L tag list resolved by
            ``build_validation_report`` (enriched tags when available, raw otherwise).
        collected_issues (list[ValidationIssue]): Issues already collected for the
            session; consulted only for the LLR-036.2 symbol-level dedup.

    Returns:
        list[ValidationIssue]: Supplemental ERROR issues, one per uncovered
        schema-incomplete tag, in tag order.

    Raises:
        None

    Data Flow:
        - Build the covered-symbol set from collected issues with ``artifact == "a2l"``,
          ``severity == ERROR``, and a non-empty ``symbol`` (casefolded); symbol-less
          issues such as ``A2L_STRUCTURE_ERROR`` never suppress (LLR-036.2).
        - Key each tag on ``tag.get("schema_ok") is False`` — an absent key or ``None``
          (raw/un-enriched tags) yields NO issue, so schema-complete fixtures and raw
          tag dicts stay issue-free (LLR-036.1, A-M2).
        - Skip tags whose casefolded name is covered; emit the rest with ``symbol`` /
          ``address`` / ``reason`` populated. Nameless tags carry ``symbol=None`` and a
          message falling back to address context. Messages are scrubbed automatically
          by the ``ValidationIssue`` constructor (``validation/model.py`` — consumed,
          not edited).

    Dependencies:
        Uses:
            - ``ValidationIssue`` / ``ValidationSeverity``
        Used by:
            - ``build_validation_report`` (both report branches, LLR-036.3)

    Example:
        >>> issues = supplemental_a2l_row_issues(
        ...     [{"name": "T1", "schema_ok": False, "reason": "missing address/length"}],
        ...     [],
        ... )
        >>> issues[0].code
        'A2L_TAG_SCHEMA_INCOMPLETE'
    """
    covered = {
        issue.symbol.casefold()
        for issue in collected_issues
        if issue.artifact == "a2l"
        and issue.severity == ValidationSeverity.ERROR
        and issue.symbol
    }
    supplemental: list[ValidationIssue] = []
    for tag in tags_for_validation:
        if tag.get("schema_ok") is not False:
            continue
        name = str(tag.get("name") or "").strip()
        if name and name.casefold() in covered:
            continue
        address = tag.get("address")
        address_value = address if isinstance(address, int) else None
        reason = str(tag.get("reason") or "").strip() or "incomplete schema"
        if name:
            message = f"A2L tag '{name}' is schema-incomplete: {reason}."
        elif address_value is not None:
            message = (
                f"Unnamed A2L tag at address 0x{address_value:X} is "
                f"schema-incomplete: {reason}."
            )
        else:
            message = f"Unnamed A2L tag (no address recorded) is schema-incomplete: {reason}."
        supplemental.append(
            ValidationIssue(
                code="A2L_TAG_SCHEMA_INCOMPLETE",
                severity=ValidationSeverity.ERROR,
                message=message,
                artifact="a2l",
                symbol=name or None,
                address=address_value,
            )
        )
    return supplemental


def supplemental_a2l_oversized_address_issues(
    tags_for_validation: list[dict],
) -> list[ValidationIssue]:
    """
    Summary:
        Emit one WARNING ``ValidationIssue`` (code ``A2L_ADDRESS_EXCEEDS_32BIT``)
        per A2L tag whose parsed ``address`` is an ``int`` strictly greater than
        ``0xFFFFFFFF`` — the 32-bit address ceiling (US-066 / LLR-066.1). A tag
        whose address is ``<= 0xFFFFFFFF``, ``None``, or non-``int`` yields no
        issue. This is a TUI-side supplemental producer (sibling of
        ``supplemental_a2l_row_issues``) so the engine-frozen ``validation/``
        package is not edited.

    Args:
        tags_for_validation (list[dict]): Effective A2L tag list resolved by
            ``build_validation_report`` (enriched tags when available, raw
            otherwise). Each tag's ``address`` is a parsed ``int`` or ``None``
            (``tui/a2l.py`` reads ``ECU_ADDRESS`` via ``int(token, 0)``).

    Returns:
        list[ValidationIssue]: Supplemental WARNING issues, one per oversized
        tag, in tag order. The ``message`` embeds the file-derived tag name as
        a plain literal (no Rich markup) so the markup-safe issues render
        (``IssueRow`` via ``safe_text``) displays a hostile name literally
        (LLR-066.3, C-17).

    Raises:
        None

    Data Flow:
        - Key each tag on ``isinstance(address, int) and address > 0xFFFFFFFF``;
          any other address (``None``/string/absent) is skipped (A-1 guard).
        - Build a plain message naming the tag (or its address when nameless)
          and the offending hex address; the ``ValidationIssue`` constructor
          scrubs control/ANSI chars from the message (``validation/model.py`` —
          consumed, not edited).

    Dependencies:
        Uses:
            - ``ValidationIssue`` / ``ValidationSeverity``
        Used by:
            - ``build_validation_report`` (both report branches, LLR-066.2)

    Example:
        >>> issues = supplemental_a2l_oversized_address_issues(
        ...     [{"name": "BIG", "address": 0x1_0000_0000}]
        ... )
        >>> issues[0].code
        'A2L_ADDRESS_EXCEEDS_32BIT'
    """
    supplemental: list[ValidationIssue] = []
    for tag in tags_for_validation:
        address = tag.get("address")
        if not isinstance(address, int) or address <= 0xFFFFFFFF:
            continue
        name = str(tag.get("name") or "").strip()
        if name:
            message = (
                f"A2L tag '{name}' address 0x{address:X} exceeds the 32-bit "
                f"address range (> 0xFFFFFFFF)."
            )
        else:
            message = (
                f"Unnamed A2L tag address 0x{address:X} exceeds the 32-bit "
                f"address range (> 0xFFFFFFFF)."
            )
        supplemental.append(
            ValidationIssue(
                code="A2L_ADDRESS_EXCEEDS_32BIT",
                severity=ValidationSeverity.WARNING,
                message=message,
                artifact="a2l",
                symbol=name or None,
                address=address,
            )
        )
    return supplemental


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
        - In BOTH branches, when the effective tag list is non-empty, merge the
          ``supplemental_a2l_row_issues`` output (US-032 red-row reconcile) and the
          ``supplemental_a2l_oversized_address_issues`` output (US-066 >32-bit
          WARNING) into the collected issues before the ``dedupe_issues`` call
          (LLR-036.3 / LLR-066.2).
        - De-duplicate and return the finalized issue list with optional coverage text.

    Dependencies:
        Uses:
            - ``validate_mac_records``
            - ``validate_artifact_consistency``
            - ``validate_a2l_internal_issues``
            - ``supplemental_a2l_row_issues``
            - ``supplemental_a2l_oversized_address_issues``
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
        if tags_for_validation:
            mac_only_issues = mac_only_issues + supplemental_a2l_row_issues(
                tags_for_validation, mac_only_issues
            )
            mac_only_issues = mac_only_issues + supplemental_a2l_oversized_address_issues(
                tags_for_validation
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
    merged_issues = report.issues + extra_a2l_issues
    if tags_for_validation:
        merged_issues = merged_issues + supplemental_a2l_row_issues(
            tags_for_validation, merged_issues
        )
        merged_issues = merged_issues + supplemental_a2l_oversized_address_issues(
            tags_for_validation
        )
    report.issues = dedupe_issues(merged_issues)
    issues = list(report.issues)
    if not any(issue.severity == ValidationSeverity.ERROR for issue in issues):
        logger.debug("Validation report produced with no hard errors.")
    coverage_line = (
        f"Coverage MAC->S19={report.coverage.mac_in_s19_pct():.1f}%  "
        f"A2L->S19={report.coverage.a2l_in_s19_pct():.1f}%  "
        f"A2L<->MAC={report.coverage.a2l_mac_match_pct():.1f}%"
    )
    return report, issues, coverage_line
