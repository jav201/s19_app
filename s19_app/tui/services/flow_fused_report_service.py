"""Flow Builder — the FUSED multi-image report (batch-70 FB-P2, R-TUI-099).

A variant-scoped run executes one flow over V images and must leave the
operator with ONE document, not V of them — N files simply re-create the manual
collation this feature exists to remove (D-4).

**Why this is a separate module from ``flow_report_service``.** AC-6 requires an
unscoped run to be byte-identical to today's single-image path. Branching inside
``compose_flow_report`` would make that a property of a conditional — something a
later edit can quietly break. Composing the fused document HERE means the
single-image composer is not edited at all, so the byte-identity is structural.

Everything file-derived (flow name, ``variant_id``, block summaries, findings)
enters through the batch-62 ``md_safe`` path re-exported by
``flow_report_service``; every glyph, label and address is enum/int-derived.

No Textual import (service-layer contract C-7).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .flow_model import (
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    BlockResult,
    FusedFlowRunResult,
)
from .flow_report_service import (
    FLOW_REPORT_MAX_TOTAL_BYTES,
    REPORT_BODY_TIMESTAMP_FORMAT,
    STATUS_CLEAN,
    STATUS_FAILED,
    STATUS_ISSUES,
    _default_now,
    _display_path,
    _fmt_ranges,
    _md_safe,
    _redact_absolute_paths,
    _STATUS_GLYPH,
)
from .report_service import (
    REPORTS_DIR_NAME,
    _ByteBudget,
    _line_bytes,
    _report_filename,
    document_bytes,
)

#: Per-variant ledger-row cap. Charged in the PRODUCER (LLR-104.5): the cap
#: limits how many rows are FORMATTED, not how many are written. batch-63's
#: Phase-2 finding was precisely that bounding output does not bound traversal.
MAX_FUSED_LEDGER_ROWS_PER_VARIANT = 60

#: Per-variant findings cap, charged the same way. Per VARIANT rather than per
#: document so one pathological image cannot evict the others' evidence (D-7).
MAX_FUSED_FINDINGS_PER_VARIANT = 60

#: Flow-status → report label. The report keeps its OWN vocabulary, matching
#: ``flow_report_service`` (m-6) — enum-derived, never file-derived.
_FLOW_STATUS_LABEL = {
    FLOW_STATUS_OK: STATUS_CLEAN,
    FLOW_STATUS_ISSUES: STATUS_ISSUES,
    FLOW_STATUS_ERROR: STATUS_FAILED,
}

#: The fused document's section headings, in order — the structural threshold.
FUSED_SECTION_HEADINGS = ("## Variant summary", "## Variant details")


@dataclass
class FusedVariantSection:
    """One variant's slice of the fused report.

    Args:
        variant_id (str): File-derived identity; rendered through ``md_safe``.
        status (str): That variant's own ``FLOW_STATUS_*`` outcome.
        block_results (Sequence[BlockResult]): Its per-block outcomes.
        written_paths (Sequence[Path]): Its image outputs.
        image_ranges (Sequence[Tuple[int, int]]): Its final address footprint.
    """

    variant_id: str
    status: str
    block_results: Sequence[BlockResult] = field(default_factory=tuple)
    written_paths: Sequence[Path] = field(default_factory=tuple)
    image_ranges: Sequence[Tuple[int, int]] = field(default_factory=tuple)


@dataclass
class FusedFlowReportState:
    """The whole state a fused report composes from (D-4).

    Args:
        flow_name (str): The flow's display name (untrusted — markup-safe on use).
        status (str): The roll-up across variants (D-5).
        sections (Sequence[FusedVariantSection]): One per EXECUTED variant, in
            plan order.
        n_ok (int): Variants that finished clean.
        n_issues (int): Variants that finished with advisories.
        n_error (int): Variants that failed.
        project_dir (Optional[Path]): Base used to render written paths relative,
            so absolute host paths never leak into a shareable record.
    """

    flow_name: str
    status: str
    sections: Sequence[FusedVariantSection] = field(default_factory=tuple)
    n_ok: int = 0
    n_issues: int = 0
    n_error: int = 0
    project_dir: Optional[Path] = None


def build_fused_report_state(
    flow_name: str,
    fused: FusedFlowRunResult,
    project_dir: Optional[Path] = None,
) -> FusedFlowReportState:
    """Project a :class:`FusedFlowRunResult` onto the report's state shape.

    Summary:
        A pure projection — one :class:`FusedVariantSection` per variant
        outcome, in plan order, carrying the counts already rolled up by
        ``flow_execution_service._roll_up_variants``. The counts are copied
        rather than recomputed so the report and the run can never disagree
        about what ran.

    Args:
        flow_name (str): The executed flow's name.
        fused (FusedFlowRunResult): The multi-image run outcome.
        project_dir (Optional[Path]): The active project directory.

    Returns:
        FusedFlowReportState: The composer's input.

    Data Flow:
        - ``fused.variant_outcomes`` → ``sections`` (1:1, order preserved).

    Dependencies:
        Used by:
            - write_fused_flow_report
            - s19_app.tui.app.S19TuiApp.on_flow_builder_panel_run_requested
    """
    return FusedFlowReportState(
        flow_name=flow_name,
        status=fused.status,
        sections=[
            FusedVariantSection(
                variant_id=outcome.variant_id,
                status=outcome.result.status,
                block_results=outcome.result.block_results,
                written_paths=outcome.result.written_paths,
                image_ranges=outcome.result.image_ranges,
            )
            for outcome in fused.variant_outcomes
        ],
        n_ok=fused.n_ok,
        n_issues=fused.n_issues,
        n_error=fused.n_error,
        project_dir=project_dir,
    )


def _summary_row(section: FusedVariantSection) -> str:
    """Render one variant's row of the always-emitted summary table."""
    label = _FLOW_STATUS_LABEL.get(section.status, section.status)
    glyph = _STATUS_GLYPH.get(section.status, "·")
    findings = sum(len(br.findings) + len(br.diagnostics) for br in section.block_results)
    return (
        f"| {_md_safe(section.variant_id)} | {glyph} {_md_safe(label)} | "
        f"{len(section.block_results)} | {findings} |"
    )


def _variant_detail_lines(section: FusedVariantSection) -> Tuple[List[str], List[str]]:
    """Produce one variant's detail lines, bounded IN THIS PRODUCER (LLR-104.5).

    Summary:
        Format at most :data:`MAX_FUSED_LEDGER_ROWS_PER_VARIANT` ledger rows and
        :data:`MAX_FUSED_FINDINGS_PER_VARIANT` findings for this variant. The
        caps are applied with :func:`itertools.islice` over the source
        sequences, so a variant carrying N ≫ cap rows costs ``cap`` formatting
        operations rather than N — the cost is charged where it is PAID, not at
        the writer, because bounding output does not bound traversal (batch-63
        Phase-2). The dropped counts come from ``len()``, which is O(1) and
        traverses nothing.

    Args:
        section (FusedVariantSection): The variant to render.

    Returns:
        Tuple[List[str], List[str]]: ``(detail_lines, cut_notes)`` — the cut
        notes name the variant, the section and the dropped count, because a
        silent truncation in an evidentiary document reads as "covered
        everything" (D-7).

    Dependencies:
        Used by:
            - compose_fused_flow_report
    """
    lines: List[str] = ["| # | Block | Status | Summary |",
                        "|---|-------|--------|---------|"]
    for br in islice(section.block_results, MAX_FUSED_LEDGER_ROWS_PER_VARIANT):
        glyph = _STATUS_GLYPH.get(br.status, "·")
        lines.append(
            f"| {br.index + 1} | {_md_safe(br.kind.upper())} | "
            f"{glyph} {_md_safe(br.status)} | {_md_safe(br.summary)} |"
        )
    lines.append("")

    cut_notes: List[str] = []
    dropped_rows = max(0, len(section.block_results) - MAX_FUSED_LEDGER_ROWS_PER_VARIANT)
    if dropped_rows:
        cut_notes.append(
            f"ledger rows: {dropped_rows} omitted "
            f"(cap {MAX_FUSED_LEDGER_ROWS_PER_VARIANT} per variant)"
        )

    # The findings budget is per VARIANT, shared across that variant's blocks —
    # a per-block cap would let a variant with many blocks multiply its way past
    # the bound, which is the same product-law trap batch-65 measured.
    remaining = MAX_FUSED_FINDINGS_PER_VARIANT
    # Counted over EVERY block, not only the rendered ones: a variant with more
    # blocks than the ledger cap still has findings in the blocks past the cut,
    # and reporting a drop count that silently excluded them would be the very
    # under-statement this notice exists to prevent. ``len`` is O(1) per block,
    # so this stays O(blocks) and formats nothing.
    total_findings = sum(
        len(br.findings) + len(br.diagnostics) for br in section.block_results
    )
    finding_lines: List[str] = []
    for br in islice(section.block_results, MAX_FUSED_LEDGER_ROWS_PER_VARIANT):
        label = f"- **[{_md_safe(br.kind.upper())} #{br.index + 1}]**"
        for finding in islice(br.findings, max(0, remaining)):
            remaining -= 1
            finding_lines.append(
                f"{label} ({_md_safe(getattr(finding, 'severity', 'warning'))}) "
                f"{_md_safe(_redact_absolute_paths(getattr(finding, 'message', finding)))}"
            )
        for diagnostic in islice(br.diagnostics, max(0, remaining)):
            remaining -= 1
            finding_lines.append(
                f"{label} (diagnostic) {_md_safe(_redact_absolute_paths(diagnostic))}"
            )
    if finding_lines:
        lines.extend(finding_lines)
        lines.append("")
    dropped_findings = max(0, total_findings - (MAX_FUSED_FINDINGS_PER_VARIANT - remaining))
    if dropped_findings:
        cut_notes.append(
            f"findings: {dropped_findings} omitted "
            f"(cap {MAX_FUSED_FINDINGS_PER_VARIANT} per variant)"
        )
    return lines, cut_notes


def compose_fused_flow_report(
    state: FusedFlowReportState, generated_at: datetime
) -> str:
    """Compose the fused multi-image markdown report — pure and deterministic.

    Summary:
        Emit a header carrying the roll-up AND its inversion (D-5), a summary
        table with one ALWAYS-emitted row per variant, then one detail section
        per variant. The per-variant heading, status line and cut notice are
        emitted unconditionally, so no amount of budget pressure can make a
        variant disappear from the document — "every variant is still
        represented" (AC-5) is a structural property here, not a hope.

    Args:
        state (FusedFlowReportState): The fused run state.
        generated_at (datetime): The generation instant (injected — the same
            state and instant always produce byte-identical output).

    Returns:
        str: The markdown document.

    Data Flow:
        - ``state.sections`` → summary rows → per-variant detail (producer-capped)
          → budget-checked join.

    Dependencies:
        Uses:
            - _variant_detail_lines (the per-variant producer bound)
            - flow_report_service._md_safe / _fmt_ranges / _display_path (reuse)
            - report_service._ByteBudget / _line_bytes (reuse, not fork)
        Used by:
            - write_fused_flow_report
    """
    budget = _ByteBudget(limit=FLOW_REPORT_MAX_TOTAL_BYTES)
    lines: List[str] = []
    truncated: List[str] = []

    def put(batch: Sequence[str], section: str) -> bool:
        if not budget.fits(_line_bytes(batch)):
            truncated.append(section)
            return False
        budget.consume(_line_bytes(batch))
        lines.extend(batch)
        return True

    executed = len(state.sections)
    put(
        [
            f"# Fused flow report — {_md_safe(state.flow_name)}",
            "",
            f"- **Generated:** {generated_at.strftime(REPORT_BODY_TIMESTAMP_FORMAT)}",
            f"- **Status:** {_FLOW_STATUS_LABEL.get(state.status, state.status)}",
            f"- **Variants executed:** {executed}",
            f"- **Outcome counts:** {state.n_ok} ok / {state.n_issues} issues / "
            f"{state.n_error} error",
            "",
        ],
        "header",
    )

    summary = ["## Variant summary", "", "| Variant | Status | Blocks | Findings |",
               "|---------|--------|--------|----------|"]
    summary.extend(_summary_row(section) for section in state.sections)
    if not state.sections:
        summary.append("| (none) | — | 0 | 0 |")
    summary.append("")
    put(summary, "Variant summary")

    put(["## Variant details", ""], "Variant details")
    for section in state.sections:
        detail, cut_notes = _variant_detail_lines(section)
        # AC-3: the heading + status + footprint + any cut notice are emitted
        # OUTSIDE the budget check, so every executed variant keeps exactly one
        # section even when its rows do not fit.
        head = [
            f"### {_md_safe(section.variant_id)}",
            "",
            f"- **Status:** "
            f"{_FLOW_STATUS_LABEL.get(section.status, section.status)}",
            f"- **Footprint:** {_fmt_ranges(section.image_ranges)}",
        ]
        if section.written_paths:
            head.extend(
                f"- **Wrote:** {_md_safe(_display_path(path, state.project_dir))}"
                for path in section.written_paths
            )
        head.append("")
        # Emitted OUTSIDE the budget gate on purpose (AC-3/AC-5) — the bytes are
        # still CHARGED so the budget stays honest, but a variant is never
        # allowed to vanish because an earlier one was expensive. The overshoot
        # this permits is O(variants x ~6 lines), which the per-variant producer
        # caps above already bound.
        lines.extend(head)
        budget.consume(_line_bytes(head))
        if not put(detail, f"details[{section.variant_id}]"):
            cut_notes.append("detail table omitted (document byte budget)")
        if cut_notes:
            cut = [
                f"> **Cut in `{_md_safe(section.variant_id)}`:** "
                f"{'; '.join(cut_notes)}.",
                "",
            ]
            lines.extend(cut)
            budget.consume(_line_bytes(cut))

    if truncated:
        lines.extend([
            "> **Truncated:** the fused report exceeded its "
            f"{FLOW_REPORT_MAX_TOTAL_BYTES:,}-byte budget; omitted section(s): "
            f"{', '.join(truncated)}.",
            "",
        ])

    lines.append("---")
    lines.append("*Generated by the s19_app Flow Builder (FB-P2, fused run).*")
    return "\n".join(lines)


def write_fused_flow_report(
    state: FusedFlowReportState,
    project_dir: Path,
    now_fn=None,
) -> Path:
    """Compose and write the fused report under ``<project>/reports/`` (D-8).

    Summary:
        Reuses ``report_service._report_filename`` so the fused document lands
        inside ``REPORT_FILENAME_REGEX`` and the shipped ``list_project_reports``
        / ``ReportViewerScreen`` pick it up with no viewer change at all. No
        file-derived string reaches the path — the directory is code-derived and
        the name timestamp-derived, so a hostile flow or variant name can only
        ever appear in report CONTENT.

    Args:
        state (FusedFlowReportState): The fused run state to report.
        project_dir (Path): The active project directory.
        now_fn (Optional[Callable[[], datetime]]): Injectable clock.

    Returns:
        Path: The written report path.

    Raises:
        OSError: Propagated from ``mkdir``/``write_bytes``.
        FileExistsError: From ``_report_filename`` when all same-second slots
            are taken — never a silent overwrite.

    Dependencies:
        Uses:
            - compose_fused_flow_report
            - report_service._report_filename / REPORTS_DIR_NAME (reuse, not fork)
        Used by:
            - s19_app.tui.app.S19TuiApp.on_flow_builder_panel_run_requested
    """
    clock = now_fn if now_fn is not None else _default_now
    generated_at = clock()
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    target = reports_dir / _report_filename(reports_dir, generated_at)
    target.write_bytes(
        document_bytes(compose_fused_flow_report(state, generated_at))
    )
    return target
