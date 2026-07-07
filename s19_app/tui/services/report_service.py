"""
Markdown project-report generator — batch-07 E7 (HLR-007).

Headless service: :func:`generate_project_report` writes one Markdown
report to ``<project>/reports/<UTC timestamp>-report.md`` from exactly the
LLR-007.8 input set — the per-variant C-6 producer objects
(``ChangeSummary`` / ``CheckRunResult`` riding ``VariantExecutionResult``),
each variant's POST-CHANGE memory map (``VariantExecutionResult.mem_map``,
captured by the E6 execution layer on request), the ``ProjectVariantSet``
inventory, :class:`ReportOptions`, and the tool version. Before-values
always come from ``ChangeSummaryEntry.before_bytes`` — this module never
re-parses an image (no parser import) and never imports Textual code
(LLR-007.1).

Hexdumps reuse the plain-string ``hexview.render_hex_view`` renderer —
never the Rich renderer (LLR-007.3). Each modified region expands to the
row-aligned window
``[max(0, align16(start - context_bytes)),
min(align16_up(end + context_bytes), align16_up(image_top)))``
(LLR-007.2 + F-Q-06, upper bound clamped at the aligned image top so no
all-gap rows are dumped past the highest mapped address); windows whose row
ranges overlap or touch MERGE into one block; addresses inside a window
that are absent from the memory map render through the renderer's existing
gap convention (blank hex cell, ``.`` in the ASCII gutter).

Size discipline (LLR-007.6): at most ``REPORT_MAX_REGIONS_PER_VARIANT``
regions are dumped per variant and the whole document is budgeted against
``REPORT_MAX_TOTAL_BYTES`` at hexdump-block granularity — a cap firing
always writes an explicit in-document ``TRUNCATED`` marker stating the
omitted count plus a truncation-appendix entry, never a silent cut.

Confidentiality (F-S-07): reports carry raw memory bytes. They are written
ONLY under the gitignored ``.s19tool/`` tree (``reports/`` inside the
project work area), this module performs NO logging at all — so report
body content can never reach the rotating log — and its tests use
synthetic in-memory fixtures / public example data exclusively.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from ...version import __version__
from ..changes import DISPOSITION_APPLIED
from ..hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view
from ..legend import LEGEND_TABLE
from .entropy_service import ENTROPY_BANDS, compute_entropy
from .report_addendum import DeclaredRegion
from ..models import ProjectVariantSet
from .variant_execution_service import (
    SCOPE_ACTIVE,
    SCOPE_ALL,
    SCOPE_ASSIGNMENTS,
    VariantExecutionResult,
)

#: Default ± surrounding-byte count of every modified-region hexdump
#: (LLR-007.2; US-004 "±64, adjustable").
REPORT_CONTEXT_BYTES_DEFAULT = 64

#: Upper bound of the ``context_bytes`` domain (F-S-05). 4096 bytes of
#: context per region keeps the worst-case window at 512+ rows, the
#: per-region ``MAX_HEX_ROWS`` ceiling — measured against the
#: ``make_large_s19`` fixture in the E7 verification run
#: (``assumed — verify per-regime`` in the spec; measurement recorded in
#: the E7 review packet).
REPORT_CONTEXT_BYTES_MAX = 4096

#: Maximum modified regions dumped per variant (LLR-007.6;
#: ``assumed — verify per-regime``, measured at E7 — see review packet).
REPORT_MAX_REGIONS_PER_VARIANT = 128

#: Whole-document byte budget (LLR-007.6). Enforced at hexdump-block
#: granularity: a block that would push the document past the budget is
#: omitted with an explicit marker (the marker itself, like the bounded
#: header/table content, is allowed past the budget — explicit beats
#: silent).
REPORT_MAX_TOTAL_BYTES = 2_097_152

#: ``ReportOptions.execution_mode`` domain (LLR-007.4 (a) / F-A-17).
REPORT_MODE_BATCH = "batch"
REPORT_MODE_PER_ASSIGNMENT = "per-assignment"
REPORT_MODE_ACTIVE = "active-only"
REPORT_EXECUTION_MODES: tuple[str, ...] = (
    REPORT_MODE_BATCH,
    REPORT_MODE_PER_ASSIGNMENT,
    REPORT_MODE_ACTIVE,
)

#: ``ReportOptions.assignment_source`` domain — whether the executed
#: variant→file mapping came from ``project.json`` or from the LLR-006.1
#: manifest-absent default (recorded in the header per LLR-007.4 (a)).
REPORT_SOURCE_MANIFEST = "manifest"
REPORT_SOURCE_DEFAULT = "default"
REPORT_ASSIGNMENT_SOURCES: tuple[str, ...] = (
    REPORT_SOURCE_MANIFEST,
    REPORT_SOURCE_DEFAULT,
)

#: Report filename timestamp format — UTC, lexicographic == chronological
#: across seconds (LLR-007.5).
REPORT_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"

#: The single authoritative report-filename regex (LLR-007.5 / F-Q-05).
REPORT_FILENAME_REGEX = re.compile(r"^\d{8}T\d{6}Z(-\d{2})?-report\.md$")

#: Reports subdirectory inside a project work area, created on demand
#: (LLR-007.7).
REPORTS_DIR_NAME = "reports"

#: E6 execution-scope token → report ``execution_mode`` token (F-A-17),
#: so the E8 trigger records HOW the reported run was scoped without any
#: report vocabulary leaking into ``app.py`` (LLR-008.5).
EXECUTION_SCOPE_TO_REPORT_MODE: dict[str, str] = {
    SCOPE_ACTIVE: REPORT_MODE_ACTIVE,
    SCOPE_ALL: REPORT_MODE_BATCH,
    SCOPE_ASSIGNMENTS: REPORT_MODE_PER_ASSIGNMENT,
}

#: Injectable UTC clock type (LLR-007.5 ``now_fn``, the B-4 pattern).
NowFn = Callable[[], datetime]


def _default_now() -> datetime:
    """
    Summary:
        Return the current UTC time — the default ``now_fn`` clock.

    Returns:
        datetime: Timezone-aware ``datetime.now(timezone.utc)``.

    Dependencies:
        Used by:
            - generate_project_report
    """
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ReportOptions:
    """
    Summary:
        Per-invocation report knobs (LLR-007.2): the hexdump context size,
        the execution mode recorded in the header (F-A-17), and the
        manifest-or-default assignment source. NOT persisted anywhere —
        every report generation supplies its own options.

    Args:
        context_bytes (int): ± surrounding bytes per modified-region
            hexdump. Domain ``0 <= context_bytes <=
            REPORT_CONTEXT_BYTES_MAX`` — an out-of-domain value raises ONE
            explicit ``ValueError`` at construction, never a silent clamp
            (F-S-05).
        execution_mode (str): One token of :data:`REPORT_EXECUTION_MODES`
            — how the reported run was scoped (LLR-007.4 (a)).
        assignment_source (str): One token of
            :data:`REPORT_ASSIGNMENT_SOURCES` — whether the variant→file
            mapping came from ``project.json`` or the manifest-absent
            default.
        include_legend (bool): When ``True`` (default), the report emits the
            classification-legend section (LLR-022.2) from
            :data:`s19_app.tui.legend.LEGEND_TABLE`. ``False`` omits it.
        declared_regions (Tuple[DeclaredRegion, ...]): Operator-declared memory
            regions (LLR-024.2). When non-empty, the report emits an addendum
            listing each region and the modifications/issues whose address
            falls inside it. Each entry must be a :class:`DeclaredRegion`.

    Returns:
        None: Frozen dataclass container.

    Raises:
        ValueError: When ``context_bytes`` is not an ``int`` inside the
            F-S-05 domain, or ``execution_mode`` /
            ``assignment_source`` is not a domain token.

    Data Flow:
        - Built by the TUI report dialog (E8) or a headless caller.
        - Consumed by :func:`generate_project_report` (header lines,
          window math).

    Dependencies:
        Used by:
            - generate_project_report
            - tests/test_report_service.py

    Example:
        >>> ReportOptions().context_bytes
        64
    """

    context_bytes: int = REPORT_CONTEXT_BYTES_DEFAULT
    execution_mode: str = REPORT_MODE_BATCH
    assignment_source: str = REPORT_SOURCE_DEFAULT
    include_legend: bool = True
    include_entropy: bool = True
    declared_regions: Tuple[DeclaredRegion, ...] = ()

    def __post_init__(self) -> None:
        """
        Summary:
            Validate every field against its domain — one explicit
            ``ValueError`` per F-S-05, never a silent clamp.

        Raises:
            ValueError: On any out-of-domain field value.
        """
        if (
            not isinstance(self.context_bytes, int)
            or self.context_bytes < 0
            or self.context_bytes > REPORT_CONTEXT_BYTES_MAX
        ):
            raise ValueError(
                f"context_bytes must be an integer in "
                f"0..{REPORT_CONTEXT_BYTES_MAX}, got "
                f"{self.context_bytes!r} - the value is rejected, not "
                f"clamped"
            )
        if self.execution_mode not in REPORT_EXECUTION_MODES:
            raise ValueError(
                f"execution_mode must be one of {REPORT_EXECUTION_MODES}, "
                f"got {self.execution_mode!r}"
            )
        if self.assignment_source not in REPORT_ASSIGNMENT_SOURCES:
            raise ValueError(
                f"assignment_source must be one of "
                f"{REPORT_ASSIGNMENT_SOURCES}, got "
                f"{self.assignment_source!r}"
            )
        if not isinstance(self.include_legend, bool):
            raise ValueError(
                f"include_legend must be a bool, got "
                f"{self.include_legend!r}"
            )
        if not isinstance(self.include_entropy, bool):
            raise ValueError(
                f"include_entropy must be a bool, got "
                f"{self.include_entropy!r} - the value is rejected, not "
                f"coerced"
            )
        for region in self.declared_regions:
            if not isinstance(region, DeclaredRegion):
                raise ValueError(
                    f"declared_regions entries must be DeclaredRegion, got "
                    f"{region!r}"
                )


def _align16(value: int) -> int:
    """Round ``value`` DOWN to a 16-byte (``HEX_WIDTH``) boundary."""
    return (value // HEX_WIDTH) * HEX_WIDTH


def _align16_up(value: int) -> int:
    """Round ``value`` UP to a 16-byte (``HEX_WIDTH``) boundary."""
    return ((value + HEX_WIDTH - 1) // HEX_WIDTH) * HEX_WIDTH


def compute_hexdump_windows(
    regions: Sequence[Tuple[int, int]],
    context_bytes: int,
    image_top: int,
) -> List[Tuple[int, int]]:
    """
    Summary:
        Expand each modified region to its row-aligned hexdump window and
        MERGE windows whose row ranges overlap or touch (LLR-007.2 +
        F-Q-06) so every row is dumped at most once.

    Args:
        regions (Sequence[Tuple[int, int]]): Half-open ``(start, end)``
            modified byte ranges (the ``applied`` summary entries), in
            document order.
        context_bytes (int): ± surrounding bytes per region (already
            domain-validated by :class:`ReportOptions`).
        image_top (int): EXCLUSIVE top of the mapped image — highest
            mapped address + 1 — so a top byte sitting exactly on a row
            boundary still gets its full row.

    Returns:
        List[Tuple[int, int]]: Merged half-open windows, ascending, each
        bound a multiple of ``HEX_WIDTH``:
        ``[max(0, align16(start - c)), min(align16_up(end + c),
        align16_up(image_top)))`` per region before merging. The lower
        bound clamps at address 0 (no underflow); the upper bound clamps
        at the aligned image top.

    Data Flow:
        - Per region: align the context-padded bounds, clamp at 0 and at
          ``align16_up(image_top)``, drop empty windows.
        - Sort, then fold: a window starting at or before the previous
          window's end extends it (adjacency merges too — both bounds are
          row-aligned, so touching windows share no gap row).

    Dependencies:
        Uses:
            - _align16 / _align16_up
        Used by:
            - generate_project_report (via _hexdump_section)
            - tests/test_report_service.py (window-math edge fixtures)

    Example:
        >>> compute_hexdump_windows([(0x100, 0x104), (0x114, 0x118)], 0, 0x200)
        [(256, 288)]
    """
    top_aligned = _align16_up(image_top)
    windows: List[Tuple[int, int]] = []
    for start, end in regions:
        low = max(0, _align16(start - context_bytes))
        high = min(_align16_up(end + context_bytes), top_aligned)
        if high > low:
            windows.append((low, high))
    windows.sort()
    merged: List[List[int]] = []
    for low, high in windows:
        if merged and low <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return [(low, high) for low, high in merged]


def _line_bytes(lines: Sequence[str]) -> int:
    """Return the UTF-8 byte cost of ``lines`` joined with ``\\n``."""
    return sum(len(line.encode("utf-8")) + 1 for line in lines)


@dataclass(slots=True)
class _ByteBudget:
    """
    Summary:
        Running whole-document byte budget (LLR-007.6) — consumed as
        sections are emitted, queried before each hexdump block.

    Args:
        limit (int): The document budget
            (:data:`REPORT_MAX_TOTAL_BYTES`, read at call time so tests
            can shrink it).
        used (int): Bytes accounted so far.

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - generate_project_report / _hexdump_section
    """

    limit: int
    used: int = 0

    def fits(self, extra: int) -> bool:
        """Report whether ``extra`` more bytes stay within the budget."""
        return self.used + extra <= self.limit

    def consume(self, extra: int) -> None:
        """Account ``extra`` emitted bytes."""
        self.used += extra


def _format_bytes(values: Optional[Iterable[int]]) -> str:
    """
    Summary:
        Format a byte run as space-separated two-hex-digit tokens; ``None``
        (no value captured) renders as ``-``.

    Args:
        values (Optional[Iterable[int]]): Byte values 0-255, or ``None``.

    Returns:
        str: e.g. ``"01 AB FF"``, or ``"-"``.

    Dependencies:
        Used by:
            - _modifications_lines / _checklist_lines
    """
    if values is None:
        return "-"
    return " ".join(f"{value:02X}" for value in values)


def _report_filename(reports_dir: Path, timestamp: datetime) -> str:
    """
    Summary:
        Build the report filename for ``timestamp``, resolving a
        same-second collision with a zero-padded two-digit counter
        (LLR-007.5: ``<ts>-report.md``, then ``<ts>-01-report.md`` ..
        ``<ts>-99-report.md``).

    Args:
        reports_dir (Path): The project's ``reports/`` directory.
        timestamp (datetime): The (UTC) generation instant from the
            injectable clock.

    Returns:
        str: A filename matching :data:`REPORT_FILENAME_REGEX` that does
        not yet exist inside ``reports_dir``.

    Raises:
        FileExistsError: When the base name and all 99 counter slots for
            this second are taken — never a silent overwrite.

    Data Flow:
        - Format the UTC timestamp, probe the un-suffixed base name, then
          ``-01`` .. ``-99`` in order; first free slot wins.

    Dependencies:
        Used by:
            - generate_project_report
    """
    base = timestamp.strftime(REPORT_TIMESTAMP_FORMAT)
    candidate = f"{base}-report.md"
    if not (reports_dir / candidate).exists():
        return candidate
    for counter in range(1, 100):
        candidate = f"{base}-{counter:02d}-report.md"
        if not (reports_dir / candidate).exists():
            return candidate
    raise FileExistsError(
        f"100 reports already exist for second {base} - refusing to "
        f"overwrite an existing report"
    )


def list_project_reports(project_dir: Path) -> List[Path]:
    """
    Summary:
        List the project's ``reports/*.md`` newest-first (LLR-008.3): files
        matching :data:`REPORT_FILENAME_REGEX` sort by the parsed key
        ``(timestamp, NN)`` descending, with a missing ``-NN`` counter
        sorting as ``00``; non-matching ``.md`` files list LAST,
        unsorted-as-found.

    Args:
        project_dir (Path): The project work area
            (``.s19tool/workarea/<project>/``).

    Returns:
        List[Path]: Report paths, newest first, foreign ``.md`` files at
        the end. Empty when ``reports/`` does not exist or holds no
        ``.md`` file.

    Data Flow:
        - The parsed sort key is REQUIRED inside a same-second collision
          group (F-Q-05): raw filename-descending would put the
          un-suffixed base AFTER its ``-NN`` siblings, but the base is the
          group's FIRST (oldest) report — ``NN=00`` keys it correctly, so
          descending order reads ``-02``, ``-01``, base.
        - Non-``.md`` directory entries are ignored entirely (the listing
          contract is ``reports/*.md``).

    Dependencies:
        Uses:
            - REPORT_FILENAME_REGEX / REPORTS_DIR_NAME
        Used by:
            - s19_app.tui.app.S19TuiApp.action_view_reports (E8)
            - tests/test_tui_report_view.py

    Example:
        >>> list_project_reports(Path("missing"))
        []
    """
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    if not reports_dir.is_dir():
        return []
    timestamp_length = len("00000000T000000Z")
    keyed: List[Tuple[Tuple[str, int], Path]] = []
    foreign: List[Path] = []
    for path in reports_dir.iterdir():
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        match = REPORT_FILENAME_REGEX.match(path.name)
        if match is None:
            foreign.append(path)
            continue
        counter = int(match.group(1)[1:]) if match.group(1) else 0
        keyed.append(((path.name[:timestamp_length], counter), path))
    keyed.sort(key=lambda item: item[0], reverse=True)
    return [path for _key, path in keyed] + foreign


def _header_lines(
    project_name: str, generated_at: datetime, options: ReportOptions
) -> List[str]:
    """
    Summary:
        Build the (a) header section: project, UTC timestamp, tool
        version, context setting, execution mode, and the
        manifest-or-default assignment source (LLR-007.4 (a) / F-A-17).

    Args:
        project_name (str): The reported project's name.
        generated_at (datetime): The clock's generation instant.
        options (ReportOptions): The invocation knobs echoed for audit.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    return [
        f"# Project report: {project_name}",
        "",
        f"- Project: {project_name}",
        f"- Generated (UTC): {generated_at.isoformat()}",
        f"- Tool version: {__version__}",
        f"- Context bytes: {options.context_bytes}",
        f"- Execution mode: {options.execution_mode}",
        f"- Assignment source: {options.assignment_source}",
        "",
    ]


def _inventory_lines(variant_set: ProjectVariantSet) -> List[str]:
    """
    Summary:
        Build the (b) variant-inventory table from the
        ``ProjectVariantSet`` descriptors (LLR-007.4 (b)).

    Args:
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = [
        "## Variant inventory",
        "",
        "| Variant | File | Type | Active |",
        "|---|---|---|---|",
    ]
    for descriptor in variant_set.variants:
        active = "yes" if descriptor.variant_id == variant_set.active_id else "no"
        lines.append(
            f"| {descriptor.variant_id} | {descriptor.path.name} "
            f"| {descriptor.file_type} | {active} |"
        )
    lines.append("")
    return lines


def _overview_lines(
    variant_results: Sequence[VariantExecutionResult],
) -> List[str]:
    """
    Summary:
        Build the (c) consolidated overview: one row per variant with its
        execution status, applied-change count, and aggregate check
        results (LLR-007.4 (c)).

    Args:
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            execution outcomes in execution order.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - Applied count sums ``ChangeSummary.counts["applied"]`` across
          the variant's change summaries; check columns sum the
          ``CheckRunResult.aggregates`` keys.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = [
        "## Consolidated overview",
        "",
        "| Variant | Status | Changes applied | Checks passed "
        "| Checks failed | Checks uncheckable |",
        "|---|---|---|---|---|---|",
    ]
    for result in variant_results:
        applied = sum(
            summary.counts.get(DISPOSITION_APPLIED, 0)
            for summary in result.change_summaries
        )
        passed = sum(
            check.aggregates.get("passed", 0) for check in result.check_results
        )
        failed = sum(
            check.aggregates.get("failed", 0) for check in result.check_results
        )
        uncheckable = sum(
            check.aggregates.get("uncheckable", 0)
            for check in result.check_results
        )
        lines.append(
            f"| {result.variant_id} | {result.status} | {applied} "
            f"| {passed} | {failed} | {uncheckable} |"
        )
    lines.append("")
    return lines


def _modified_files_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant modified-files list: every change file that
        applied at least one entry, including the ``saved_path`` of the
        persisted patched image when present (LLR-007.4 (d) / LLR-002.7).

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = ["### Modified files", ""]
    bullets: List[str] = []
    for summary in result.change_summaries:
        if summary.counts.get(DISPOSITION_APPLIED, 0) <= 0:
            continue
        source = (
            str(summary.source_path)
            if summary.source_path is not None
            else "<in-memory document>"
        )
        bullet = (
            f"- {source} (applied entries: "
            f"{summary.counts[DISPOSITION_APPLIED]})"
        )
        if summary.saved_path is not None:
            bullet += f" - saved as `{summary.saved_path}`"
        bullets.append(bullet)
    if bullets:
        lines.extend(bullets)
    else:
        lines.append("No files were modified for this variant.")
    lines.append("")
    return lines


def _modifications_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant per-modification table — address, length,
        before, after, linkage, symbol per entry (LLR-007.4 (d)), entries
        in document order across the variant's change summaries.

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - ``before_bytes`` is ``None`` for every non-applied disposition
          (LLR-002.5) and renders as ``-`` — values come from the summary
          objects only, never from re-reading memory (LLR-007.8).

    Dependencies:
        Uses:
            - _format_bytes
        Used by:
            - generate_project_report
    """
    lines = ["### Modifications", ""]
    entries = [
        entry
        for summary in result.change_summaries
        for entry in summary.entries
    ]
    if not entries:
        lines.extend(["No change entries were executed for this variant.", ""])
        return lines
    lines.extend(
        [
            "| Address | Length | Before | After | Linkage | Symbol |",
            "|---|---|---|---|---|---|",
        ]
    )
    for entry in entries:
        lines.append(
            f"| 0x{entry.address_start:08X} "
            f"| {entry.address_end - entry.address_start} "
            f"| {_format_bytes(entry.before_bytes)} "
            f"| {_format_bytes(entry.after_bytes)} "
            f"| {entry.linkage} "
            f"| {entry.linkage_symbol or '-'} |"
        )
    lines.append("")
    return lines


def _declaration_error_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant declaration-error subsection: every
        ``ValidationIssue`` collected on the variant's change summaries
        and check results (LLR-007.4 (d) declaration-error subsection,
        per LLR-002.8 + B-2 — operator decision 2026-06-10).

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included; ``None.`` when
        no declaration fault was collected.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = ["### Declaration errors", ""]
    issues = [
        issue
        for summary in result.change_summaries
        for issue in summary.issues
    ]
    issues.extend(
        issue for check in result.check_results for issue in check.issues
    )
    if not issues:
        lines.extend(["None.", ""])
        return lines
    for issue in issues:
        line = f"- [{issue.code}] {issue.severity.value}: {issue.message}"
        if issue.address is not None:
            line += f" @ 0x{issue.address:X}"
        if issue.symbol:
            line += f" symbol={issue.symbol}"
        if issue.related_artifacts:
            line += f" related={','.join(issue.related_artifacts)}"
        lines.append(line)
    lines.append("")
    return lines


def _checklist_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant checklist tables — one table per executed
        check file with expected/actual/result per entry plus the
        aggregate counts line (LLR-007.4 (d)).

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Uses:
            - _format_bytes
        Used by:
            - generate_project_report
    """
    lines = ["### Checklists", ""]
    if not result.check_results:
        lines.extend(["No checklists were executed for this variant.", ""])
        return lines
    for check in result.check_results:
        source = (
            str(check.source_path)
            if check.source_path is not None
            else "<in-memory document>"
        )
        lines.extend(
            [
                f"#### Checklist: {source}",
                "",
                f"Passed: {check.aggregates.get('passed', 0)} - "
                f"Failed: {check.aggregates.get('failed', 0)} - "
                f"Uncheckable: {check.aggregates.get('uncheckable', 0)}",
                "",
                "| Address | Length | Expected | Actual | Result |",
                "|---|---|---|---|---|",
            ]
        )
        for entry in check.entries:
            lines.append(
                f"| 0x{entry.address_start:08X} "
                f"| {entry.address_end - entry.address_start} "
                f"| {_format_bytes(entry.expected_bytes)} "
                f"| {_format_bytes(entry.actual_bytes)} "
                f"| {entry.result} |"
            )
        lines.append("")
    return lines


def _applied_regions(
    result: VariantExecutionResult,
) -> List[Tuple[int, int]]:
    """
    Summary:
        Collect the variant's modified regions — the half-open ranges of
        every ``applied`` summary entry, in document order across change
        summaries.

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[Tuple[int, int]]: ``(address_start, address_end)`` per
        applied entry.

    Dependencies:
        Used by:
            - _hexdump_section
    """
    return [
        (entry.address_start, entry.address_end)
        for summary in result.change_summaries
        for entry in summary.entries
        if entry.disposition == DISPOSITION_APPLIED
    ]


def _hexdump_block(
    mem_map: dict[int, int], low: int, high: int
) -> List[str]:
    """
    Summary:
        Render one merged window as a fenced hexdump block through the
        plain-string ``render_hex_view`` (LLR-007.3) — explicit row bases
        cover the whole window, so unmapped addresses render via the gap
        convention.

    Args:
        mem_map (dict[int, int]): The variant's post-change memory map.
        low (int): Window start (16-byte aligned, inclusive).
        high (int): Window end (16-byte aligned, exclusive).

    Returns:
        List[str]: Markdown lines, trailing blank included. ``MAX_HEX_ROWS``
        bounds the rendered rows per block (per-region cap, LLR-007.3).

    Dependencies:
        Uses:
            - hexview.render_hex_view
        Used by:
            - _hexdump_section
    """
    row_bases = list(range(low, high, HEX_WIDTH))
    rendered = render_hex_view(mem_map, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
    return [
        f"Window 0x{low:08X}-0x{high:08X}:",
        "",
        "```text",
        *rendered.splitlines(),
        "```",
        "",
    ]


def _hexdump_section(
    result: VariantExecutionResult,
    options: ReportOptions,
    budget: _ByteBudget,
) -> Tuple[List[str], List[str]]:
    """
    Summary:
        Build the per-variant hexdump section: one merged-window block per
        modified-region cluster, enforcing both LLR-007.6 caps with
        explicit in-document ``TRUNCATED`` markers stating the exact
        omitted counts — never a silent cut.

    Args:
        result (VariantExecutionResult): One variant's execution outcome;
            ``result.mem_map`` is the post-change hexdump source
            (LLR-007.8) — when it was not captured the section states so
            and dumps nothing.
        options (ReportOptions): Supplies ``context_bytes``.
        budget (_ByteBudget): The running whole-document byte budget —
            consumed for every line this section emits; a block that no
            longer fits is omitted and counted.

    Returns:
        Tuple[List[str], List[str]]: The section's Markdown lines and the
        truncation-appendix notes it produced (empty when no cap fired).

    Data Flow:
        - Regions over :data:`REPORT_MAX_REGIONS_PER_VARIANT` → keep the
          first cap-many in document order, emit the region marker.
        - ``compute_hexdump_windows`` merges the kept regions' windows
          against ``image_top = max(mem_map) + 1``.
        - Each block is emitted only when the byte budget still fits it;
          omitted blocks end in the size marker.

    Dependencies:
        Uses:
            - _applied_regions / compute_hexdump_windows / _hexdump_block
        Used by:
            - generate_project_report
    """
    out: List[str] = []
    notes: List[str] = []

    def put(batch: Sequence[str]) -> None:
        out.extend(batch)
        budget.consume(_line_bytes(batch))

    put(["### Memory regions", ""])
    regions = _applied_regions(result)
    if not regions:
        put(["No modified regions.", ""])
        return out, notes
    if not result.mem_map:
        put(["Post-change memory map unavailable - hexdumps omitted.", ""])
        return out, notes
    total_regions = len(regions)
    if total_regions > REPORT_MAX_REGIONS_PER_VARIANT:
        omitted = total_regions - REPORT_MAX_REGIONS_PER_VARIANT
        regions = regions[:REPORT_MAX_REGIONS_PER_VARIANT]
        text = (
            f"{omitted} of {total_regions} modified regions omitted "
            f"(cap: {REPORT_MAX_REGIONS_PER_VARIANT} regions per variant)"
        )
        put([f"> TRUNCATED: {text}.", ""])
        notes.append(f"Variant '{result.variant_id}': {text}.")
    image_top = max(result.mem_map) + 1
    omitted_blocks = 0
    for low, high in compute_hexdump_windows(
        regions, options.context_bytes, image_top
    ):
        block = _hexdump_block(result.mem_map, low, high)
        if not budget.fits(_line_bytes(block)):
            omitted_blocks += 1
            continue
        put(block)
    if omitted_blocks:
        text = (
            f"{omitted_blocks} hexdump block(s) omitted "
            f"(report size cap: {REPORT_MAX_TOTAL_BYTES} bytes)"
        )
        out.extend([f"> TRUNCATED: {text}.", ""])
        notes.append(f"Variant '{result.variant_id}': {text}.")
    return out, notes


def _legend_lines() -> List[str]:
    """
    Summary:
        Render :data:`s19_app.tui.legend.LEGEND_TABLE` as a Markdown legend
        section (LLR-022.2) — one sub-heading per artifact, one bullet per
        classification giving its colour and documented meaning. Static text
        (no run data feeds it), so it is identical across every report.

    Returns:
        List[str]: Markdown lines beginning with the ``## Legend`` heading;
        each row is ``- **<classification>**[ (<colour>)] — <meaning>`` with
        the parenthetical colour shown only when it differs from the
        classification label (i.e. the Issues categories).

    Data Flow:
        - Reads the shared ``LEGEND_TABLE`` (single source with the in-app
          ``LegendScreen`` modal — no duplicated literal here).
        - Emitted by :func:`generate_project_report` when
          ``options.include_legend`` is ``True``.

    Dependencies:
        Uses:
            - s19_app.tui.legend.LEGEND_TABLE
        Used by:
            - generate_project_report
            - tests/test_report_service.py
    """
    lines: List[str] = ["## Legend", ""]
    for artifact, rows in LEGEND_TABLE.items():
        lines.append(f"### {artifact}")
        for classification, (colour, meaning) in rows.items():
            suffix = "" if classification == colour else f" ({colour})"
            lines.append(f"- **{classification}**{suffix} — {meaning}")
        lines.append("")
    return lines


def _entropy_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Render a per-variant entropy/classification section (LLR-037.2) — a
        band SUMMARY (count per band, low-confidence windows flagged) computed
        from :func:`entropy_service.compute_entropy` over the variant's
        post-change ``result.mem_map``. Band-summary only (O(bands), not
        O(windows)) — no raw byte dump — so the section stays bounded against
        the report byte budget (R-2) and adds no memory-value confidentiality
        surface beyond what the hexdump already emits.

    Args:
        result (VariantExecutionResult): The variant whose ``mem_map`` (the
            same source :func:`_hexdump_section` reads, populated when the E6
            execution layer runs with ``capture_mem_maps=True``) is classified.
            An empty or ``None`` ``mem_map`` yields a heading plus a single
            "no data" line rather than crashing.

    Returns:
        List[str]: Markdown lines beginning with the ``### Entropy`` heading;
        for a populated map, one bullet per :data:`entropy_service.ENTROPY_BANDS`
        band that has ≥1 window (``- **<band>**: <n> window(s)``, with a
        ``(<k> low-confidence)`` suffix when any of that band's windows are
        low-confidence). A map with no mapped bytes returns the heading plus
        ``No mapped bytes - entropy not computed.``.

    Data Flow:
        - ``result.mem_map`` → :func:`entropy_service.compute_entropy` →
          count windows per band label (in ``ENTROPY_BANDS`` order) →
          Markdown bullets.
        - Emitted by :func:`generate_project_report` through the budget-charged
          ``emit`` helper when ``options.include_entropy`` is ``True``, inside
          the per-variant loop immediately after the hexdump section.

    Dependencies:
        Uses:
            - entropy_service.compute_entropy / entropy_service.ENTROPY_BANDS
        Used by:
            - generate_project_report
            - tests/test_report_service.py
    """
    lines: List[str] = ["### Entropy", ""]
    mem_map = result.mem_map
    if not mem_map:
        lines.append("No mapped bytes - entropy not computed.")
        lines.append("")
        return lines
    windows = compute_entropy(mem_map)
    counts: dict[str, int] = {label: 0 for label, _lo, _hi in ENTROPY_BANDS}
    low_conf: dict[str, int] = {label: 0 for label, _lo, _hi in ENTROPY_BANDS}
    for window in windows:
        counts[window.band] += 1
        if window.low_confidence:
            low_conf[window.band] += 1
    for label, _lo, _hi in ENTROPY_BANDS:
        count = counts[label]
        if not count:
            continue
        suffix = (
            f" ({low_conf[label]} low-confidence)" if low_conf[label] else ""
        )
        lines.append(f"- **{label}**: {count} window(s){suffix}")
    lines.append("")
    return lines


def _addendum_lines(
    regions: Sequence[DeclaredRegion],
    variant_results: Sequence[VariantExecutionResult],
) -> List[str]:
    """
    Summary:
        Render the declared-region addendum (LLR-024.2): one sub-section per
        region listing the modifications and validation issues whose address
        falls within the region's inclusive ``[start, end]`` range, aggregated
        across all variants. A region with no hits renders an explicit "None.".

    Args:
        regions (Sequence[DeclaredRegion]): The operator-declared regions.
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            outcomes — the same objects the per-variant report sections walk.

    Returns:
        List[str]: Markdown lines beginning with the
        ``## Addendum: declared regions`` heading.

    Data Flow:
        - Reads each variant's change-summary entries (``address_start``) and
          the issues on its change summaries + check results
          (``ValidationIssue.address``) — the SAME address the issue renderer
          (``_declaration_error_lines``) reads (single source, TC-S3).
        - Aggregates across ALL variants regardless of ``result.status`` —
          deliberately consistent with the per-variant report sections, which
          also emit for every variant; each hit line is tagged
          ``(variant <id>)`` for traceability.
        - Emitted by :func:`generate_project_report` when
          ``options.declared_regions`` is non-empty.

    Dependencies:
        Uses:
            - DeclaredRegion.contains
        Used by:
            - generate_project_report
            - tests/test_report_service.py
    """
    lines: List[str] = ["## Addendum: declared regions", ""]
    for region in regions:
        lines.append(f"### {region.name} (0x{region.start:X}-0x{region.end:X})")
        hits: List[str] = []
        for result in variant_results:
            for summary in result.change_summaries:
                for entry in summary.entries:
                    if region.contains(entry.address_start):
                        hits.append(
                            f"- modification @ 0x{entry.address_start:X} "
                            f"(variant {result.variant_id})"
                        )
                for issue in summary.issues:
                    if issue.address is not None and region.contains(issue.address):
                        hits.append(
                            f"- issue [{issue.code}] @ 0x{issue.address:X} "
                            f"(variant {result.variant_id})"
                        )
            for check in result.check_results:
                for issue in check.issues:
                    if issue.address is not None and region.contains(issue.address):
                        hits.append(
                            f"- issue [{issue.code}] @ 0x{issue.address:X} "
                            f"(variant {result.variant_id})"
                        )
        lines.extend(hits if hits else ["None."])
        lines.append("")
    return lines


def generate_project_report(
    project_dir: Path,
    variant_results: Sequence[VariantExecutionResult],
    options: ReportOptions,
    *,
    variant_set: ProjectVariantSet,
    now_fn: Optional[NowFn] = None,
) -> Path:
    """
    Summary:
        Generate one Markdown project report under
        ``<project_dir>/reports/`` (HLR-007) and return its path. Fully
        headless: derivable exclusively from the LLR-007.8 input set —
        the C-6 objects and post-change memory maps riding
        ``variant_results``, the ``variant_set`` inventory, ``options``,
        and the tool version — no image is ever re-parsed.

    Args:
        project_dir (Path): The project work area
            (``.s19tool/workarea/<project>/``) — the gitignored
            destination root (F-S-07).
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            execution outcomes in execution order; ``mem_map`` must have
            been captured (``capture_mem_maps=True``) for hexdumps to
            appear.
        options (ReportOptions): Domain-validated invocation knobs
            (context bytes, execution mode, assignment source).
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory — the LLR-007.4 (b) table source. Keyword-only: it
            is the one LLR-007.8 input that does not ride
            ``variant_results``.
        now_fn (Optional[NowFn]): Injectable UTC clock (LLR-007.5 /
            B-4); ``None`` resolves to ``datetime.now(timezone.utc)``.

    Returns:
        Path: The written report file —
        ``reports/<UTC %Y%m%dT%H%M%SZ>-report.md``, with a zero-padded
        ``-NN`` counter on a same-second collision (LLR-007.5).

    Raises:
        ValueError: Never for in-domain options (``ReportOptions``
            validates at construction).
        FileExistsError: When 100 reports already exist for the same
            second — never a silent overwrite (LLR-007.5).

    Data Flow:
        - ``reports/`` is created on demand (LLR-007.7).
        - Sections emit in the LLR-007.4 order: (a) header, (b) variant
          inventory, (c) consolidated overview, (c2) the classification
          legend when ``options.include_legend`` (LLR-022.2), (d) one
          section per variant (modified files → modifications table →
          declaration errors → checklists → memory-region hexdumps), (d2)
          the declared-region addendum when ``options.declared_regions``
          (LLR-024.2), (e) the truncation appendix when any cap fired.
        - The whole document is budgeted against
          :data:`REPORT_MAX_TOTAL_BYTES` at hexdump-block granularity.

    Dependencies:
        Uses:
            - _header_lines / _inventory_lines / _overview_lines
            - _legend_lines / _addendum_lines
            - _modified_files_lines / _modifications_lines
            - _declaration_error_lines / _checklist_lines
            - _hexdump_section / _report_filename
        Used by:
            - The E8 report TUI action (later increment)
            - tests/test_report_service.py

    Example:
        >>> path = generate_project_report(
        ...     project_dir, results, ReportOptions(),
        ...     variant_set=variant_set,
        ... )  # doctest: +SKIP
    """
    clock = now_fn if now_fn is not None else _default_now
    generated_at = clock()
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    filename = _report_filename(reports_dir, generated_at)

    budget = _ByteBudget(limit=REPORT_MAX_TOTAL_BYTES)
    lines: List[str] = []
    notes: List[str] = []

    def emit(batch: Sequence[str]) -> None:
        lines.extend(batch)
        budget.consume(_line_bytes(batch))

    emit(_header_lines(variant_set.project_name, generated_at, options))
    emit(_inventory_lines(variant_set))
    emit(_overview_lines(variant_results))
    if options.include_legend:
        emit(_legend_lines())
    for result in variant_results:
        emit([f"## Variant: {result.variant_id}", ""])
        emit(_modified_files_lines(result))
        emit(_modifications_lines(result))
        emit(_declaration_error_lines(result))
        emit(_checklist_lines(result))
        dump_lines, dump_notes = _hexdump_section(result, options, budget)
        lines.extend(dump_lines)
        notes.extend(dump_notes)
        if options.include_entropy:
            emit(_entropy_lines(result))
    if options.declared_regions:
        emit(_addendum_lines(options.declared_regions, variant_results))
    if notes:
        emit(
            ["## Truncation appendix", ""]
            + [f"- {note}" for note in notes]
            + [""]
        )

    target = reports_dir / filename
    target.write_text("\n".join(lines), encoding="utf-8")
    return target
