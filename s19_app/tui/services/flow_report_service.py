"""Flow Builder — flow-run report generation (batch-60 FB-P1b, HLR-001/002).

Compose a markdown report of a flow run from the state assembled so far in
``run_flow``, and write it into the project ``reports/`` directory under the
SAME ``<ts>-report.md`` convention the project reports use — so
``report_service.list_project_reports`` and ``ReportViewerScreen`` surface it
with no new viewer (D-3).

Textual-free (service-layer contract C-7): stdlib + the flow model + the report
service's filename/budget primitives only.

Semantics (operator decisions, §6.5 AMD-authoritative):

- **Explicit trigger (D-1).** A report exists only because the flow carries a
  ``ReportBlock``; nothing here runs implicitly.
- **Positional (D-2).** The composer sees the state UP TO the report block, so a
  REPORT-last flow captures the whole pipeline and a mid-flow REPORT captures a
  prefix. The status is therefore a PROVISIONAL rollup.
- **Abort is an input, not an inference (AMD-4).** :class:`FlowReportState`
  carries an explicit ``aborted`` flag threaded from ``run_flow``. The composer
  MUST NOT infer failure from ``BlockResult.summary`` or status: only one of the
  nine aborting sites in ``run_flow`` uses the summary ``"error"`` (the generic
  ``except``); the eight ``_record_error`` shapes carry custom summaries
  (``"source unresolved"``, ``"no image"``, ``"write failed"``, …) and would
  misclassify a FAILED run as COMPLETED WITH ISSUES.

Markup safety (C-17, AMD-1/2/5 — the load-bearing surface):

The report embeds file-derived text (block summaries echoing a ``change_doc_ref``,
finding messages, written filenames, the flow name) and is rendered by
``textual.widgets.Markdown``, which builds ``MarkdownIt("gfm-like")`` with
**linkify enabled**. That grammar is NOT plain CommonMark: a bare ``http://…``
autolinks and ``~~x~~`` strikes through. :func:`_md_safe` is therefore written
against *that* grammar — escaping ``/`` (which defuses both ``http://host`` and
protocol-relative ``//host``, and renders invisibly) and ``~`` on top of the
usual CommonMark set, and REMOVING backticks rather than escaping them so the
helper stays context-free (backslash escapes are inert inside a code span).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    BlockResult,
)
from .report_service import (
    REPORT_MAX_TOTAL_BYTES,
    REPORTS_DIR_NAME,
    _ByteBudget,
    _line_bytes,
    _report_filename,
)

#: Whole-document byte budget for a flow report. Bound to the project-report
#: budget so a flow report can never exceed ``screens.VIEWER_SIZE_CAP_BYTES``
#: (``2 * REPORT_MAX_TOTAL_BYTES``) and be refused by its own viewer (AMD-7).
FLOW_REPORT_MAX_TOTAL_BYTES = REPORT_MAX_TOTAL_BYTES

#: Per-cell character cap. A ledger cell is one line; a file-derived summary is
#: unbounded, so it is truncated BEFORE escaping (escaping can only grow it).
MAX_REPORT_CELL_CHARS = 240

#: Per-block findings cap. ``SOURCE`` emits one finding per parser error with no
#: cap of its own, so a corrupt image would otherwise compose an unbounded report.
MAX_REPORT_FINDINGS_PER_BLOCK = 200

#: Truncation marker appended to an over-cap cell.
_TRUNCATION_MARKER = "… (truncated)"

#: Body timestamp format (pinned so the composer is byte-deterministic, m-3).
REPORT_BODY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

#: Report status labels. Deliberately the report's OWN vocabulary (a markdown
#: record), NOT ``screens_directionb._FLOW_STATUS_BANNER`` (a TUI banner) — the
#: divergence is intentional so a future reader does not "fix" it (m-6).
STATUS_CLEAN = "CLEAN"
STATUS_ISSUES = "COMPLETED WITH ISSUES"
STATUS_FAILED = "FAILED"

#: Per-status gutter glyph — enum-derived, never file-derived.
_STATUS_GLYPH = {
    BLOCK_STATUS_OK: "●",
    BLOCK_STATUS_NOTICES: "◈",
    BLOCK_STATUS_ERROR: "✖",
    BLOCK_STATUS_SKIPPED: "○",
}

#: The section headings, in order — the structural threshold (AMD-14/m-2).
SECTION_HEADINGS = (
    "## Pipeline ledger",
    "## Findings",
    "## Image footprint",
    "## Written files",
)

#: Markdown-structural characters escaped by :func:`_md_safe`. ``~`` kills
#: strikethrough and ``/`` defuses linkify — both are gfm-like extensions absent
#: from a plain CommonMark set (AMD-1).
_MD_ESCAPE = ("\\", "|", "*", "_", "[", "]", "<", ">", "#", "~", "/")


def _default_now() -> datetime:
    """Current UTC instant — the injectable clock seam (tests monkeypatch this)."""
    return datetime.now(timezone.utc)


def _md_safe(value: object, limit: int = MAX_REPORT_CELL_CHARS) -> str:
    """Render ``value`` inert inside the report's markdown grammar (C-17).

    Summary:
        Neutralise a file-derived string for embedding anywhere in the report —
        table cell, list item or heading. Control bytes are stripped and
        newlines/tabs collapsed (a cell is one line); backticks are REMOVED (not
        escaped) so the helper is context-free, because a backslash escape is
        inert inside a code span; the value is truncated BEFORE escaping (escaping
        only grows it); then every markdown-structural character is escaped.

        The escape set targets ``MarkdownIt("gfm-like")`` with linkify enabled —
        the grammar ``textual.widgets.Markdown`` actually uses — so it includes
        ``~`` (strikethrough) and ``/`` (autolink), which a CommonMark set omits.
        Escaping ``/`` renders invisibly, so paths stay readable.

    Args:
        value (object): The raw, untrusted value; rendered via ``str()``.
        limit (int): Character cap applied before escaping. Defaults to
            :data:`MAX_REPORT_CELL_CHARS`.

    Returns:
        str: Inert text, never empty — ``"(empty)"`` when nothing survives.

    Data Flow:
        - Called on every file-derived field by :func:`compose_flow_report`.

    Dependencies:
        Used by:
            - compose_flow_report

    Example:
        >>> _md_safe("a|b `c` http://x")
        'a\\\\|b c http:\\\\/\\\\/x'
    """
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch if ch >= " " else " " for ch in text)  # drop control bytes
    text = text.replace("`", "")  # context-free: remove, never escape (AMD-5)
    text = text.strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + _TRUNCATION_MARKER
    for ch in _MD_ESCAPE:  # backslash FIRST — never double-escape
        text = text.replace(ch, "\\" + ch)
    return text or "(empty)"


@dataclass
class FlowReportState:
    """The slice of run state a positional report block composes from.

    Args:
        flow_name (str): The flow's display name (untrusted — markup-safe on use).
        block_results (List[BlockResult]): The blocks executed SO FAR (D-2).
        aborted (bool): Whether the image was broken by an upstream STOP — the
            EXPLICIT failure signal (AMD-4); never inferred from a summary.
        image_ranges (Optional[Sequence[Tuple[int, int]]]): The LOCAL threaded
            ranges at this instant (``result.image_ranges`` is only assigned
            after the block loop, so it would be empty here — AMD-9).
        pre_crc_ranges (Sequence[Tuple[int, int]]): ``result.pre_crc_ranges`` as
            it stands NOW — empty when no CRC block has run yet, which is why a
            pre-CRC report legitimately omits the "Before CRC" line (AMD-9).
        written_paths (Sequence[Path]): Image outputs written so far. The report's
            own path is NOT added (AMD-11 — that is the image-output contract).
        project_dir (Optional[Path]): Base used to render written paths RELATIVE,
            so absolute host paths never leak into a shareable record (AMD-8).
    """

    flow_name: str
    block_results: List[BlockResult] = field(default_factory=list)
    aborted: bool = False
    image_ranges: Optional[Sequence[Tuple[int, int]]] = None
    pre_crc_ranges: Sequence[Tuple[int, int]] = field(default_factory=tuple)
    written_paths: Sequence[Path] = field(default_factory=tuple)
    project_dir: Optional[Path] = None


def _fmt_ranges(ranges: Optional[Sequence[Tuple[int, int]]]) -> str:
    """Render an address-range list with its byte total (enum/int-derived)."""
    if not ranges:
        return "(none)"
    parts = [f"0x{int(lo):08X}–0x{int(hi):08X}" for lo, hi in ranges]
    total = sum(int(hi) - int(lo) + 1 for lo, hi in ranges)
    return f"{', '.join(parts)}  ({total:,} bytes)"


def _display_path(path: Path, project_dir: Optional[Path]) -> str:
    """Render ``path`` relative to the project, never as an absolute host path.

    A report is a shareable record; an absolute path would disclose the operator's
    username and local directory layout (AMD-8). Falls back to the bare filename
    when the path is not under ``project_dir``.
    """
    candidate = Path(path)
    if project_dir is not None:
        try:
            return candidate.resolve().relative_to(Path(project_dir).resolve()).as_posix()
        except (ValueError, OSError):
            return candidate.name
    return candidate.name


def _provisional_status(state: FlowReportState) -> str:
    """Roll the blocks-so-far up to a report status label (LLR-001.2).

    FAILED keys on the EXPLICIT ``aborted`` flag (AMD-4) — never on a summary
    string. Otherwise any ``notices``/``error`` block or any finding means
    advisories were produced; else CLEAN.
    """
    if state.aborted:
        return STATUS_FAILED
    if any(
        br.status in {BLOCK_STATUS_NOTICES, BLOCK_STATUS_ERROR} or br.findings
        for br in state.block_results
    ):
        return STATUS_ISSUES
    return STATUS_CLEAN


def compose_flow_report(state: FlowReportState, generated_at: datetime) -> str:
    """Compose the markdown flow-run report — pure and deterministic (LLR-001.1).

    Summary:
        Emit, in order: a header block (flow name, generated timestamp,
        provisional status, block count), the **Pipeline ledger** table (one row
        per reported block), a **Findings** section, the **Image footprint**
        (``Before CRC`` only when a CRC has already run), and **Written files**.
        Every file-derived field passes :func:`_md_safe`; every glyph, label and
        address is enum/int-derived. A whole-document byte budget bounds the
        output so it can never exceed the viewer's size cap (AMD-7).

    Args:
        state (FlowReportState): The run state up to the report block.
        generated_at (datetime): The generation instant (injected — the same
            state and instant always produce byte-identical output).

    Returns:
        str: The markdown document.

    Data Flow:
        - ``state`` → per-section line lists → budget-checked join.
        - Consumed by :func:`write_flow_report`.

    Dependencies:
        Uses:
            - _md_safe / _fmt_ranges / _display_path / _provisional_status
            - report_service._ByteBudget / _line_bytes (reuse, not fork)
        Used by:
            - write_flow_report
    """
    budget = _ByteBudget(limit=FLOW_REPORT_MAX_TOTAL_BYTES)
    lines: List[str] = []
    truncated_sections: List[str] = []

    def put(batch: Sequence[str], section: str) -> bool:
        """Append ``batch`` when it fits; record the section when it does not."""
        if not budget.fits(_line_bytes(batch)):
            truncated_sections.append(section)
            return False
        budget.consume(_line_bytes(batch))
        lines.extend(batch)
        return True

    put(
        [
            f"# Flow report — {_md_safe(state.flow_name)}",
            "",
            f"- **Generated:** {generated_at.strftime(REPORT_BODY_TIMESTAMP_FORMAT)}",
            f"- **Status:** {_provisional_status(state)}",
            f"- **Blocks reported:** {len(state.block_results)} "
            "(up to the report block)",
            "",
        ],
        "header",
    )

    ledger = ["## Pipeline ledger", "", "| # | Block | Status | Summary |",
              "|---|-------|--------|---------|"]
    for br in state.block_results:
        glyph = _STATUS_GLYPH.get(br.status, "·")
        ledger.append(
            f"| {br.index + 1} | {_md_safe(br.kind.upper())} | "
            f"{glyph} {_md_safe(br.status)} | {_md_safe(br.summary)} |"
        )
    ledger.append("")
    put(ledger, "Pipeline ledger")

    findings_lines = ["## Findings", ""]
    any_finding = False
    for br in state.block_results:
        shown = list(br.findings)[:MAX_REPORT_FINDINGS_PER_BLOCK]
        for finding in shown:
            any_finding = True
            severity = getattr(finding, "severity", "warning")
            message = getattr(finding, "message", finding)
            findings_lines.append(
                f"- **[{_md_safe(br.kind.upper())} #{br.index + 1}]** "
                f"({_md_safe(severity)}) {_md_safe(message)}"
            )
        suppressed = len(br.findings) - len(shown)
        if suppressed > 0:
            any_finding = True
            findings_lines.append(
                f"- *{suppressed} more findings omitted (per-block cap "
                f"{MAX_REPORT_FINDINGS_PER_BLOCK}).*"
            )
    findings_lines.append("")
    if any_finding:
        put(findings_lines, "Findings")

    footprint = ["## Image footprint", ""]
    if state.pre_crc_ranges:
        footprint.append(f"- **Before CRC:** {_fmt_ranges(state.pre_crc_ranges)}")
    footprint.append(f"- **Final:** {_fmt_ranges(state.image_ranges)}")
    footprint.append("")
    put(footprint, "Image footprint")

    written = ["## Written files", ""]
    if state.written_paths:
        for path in state.written_paths:
            # No backtick wrapping: a code span makes backslash escapes inert and
            # lets a backtick-bearing name break out into live inline context.
            written.append(f"- {_md_safe(_display_path(path, state.project_dir))}")
    else:
        written.append("- (none)")
    written.append("")
    put(written, "Written files")

    if truncated_sections:
        lines.extend([
            "> **Truncated:** the report exceeded its "
            f"{FLOW_REPORT_MAX_TOTAL_BYTES:,}-byte budget; omitted section(s): "
            f"{', '.join(truncated_sections)}.",
            "",
        ])

    lines.append("---")
    lines.append("*Generated by the s19_app Flow Builder (FB-P1b).*")
    return "\n".join(lines)


def write_flow_report(
    state: FlowReportState,
    project_dir: Path,
    now_fn=None,
) -> Path:
    """Compose and write the report under ``<project>/reports/`` (LLR-002.1).

    Summary:
        Create the reports directory, pick a non-colliding name via the REUSED
        ``report_service._report_filename`` (never a hand-rolled name — that is
        what keeps the file inside ``REPORT_FILENAME_REGEX`` and therefore visible
        to ``list_project_reports`` and the shipped viewer, D-3), and write UTF-8.

        No file-derived string reaches the path: the directory is code-derived
        (``REPORTS_DIR_NAME``) and the filename is timestamp-derived, so a hostile
        flow NAME can only ever appear in report CONTENT.

    Args:
        state (FlowReportState): The run state to report.
        project_dir (Path): The active project directory.
        now_fn (Optional[Callable[[], datetime]]): Injectable clock; defaults to
            :func:`_default_now`.

    Returns:
        Path: The written report path.

    Raises:
        OSError: Propagated from ``mkdir``/``write_text`` — the caller
            (``run_flow``) degrades this into an error BlockResult without
            aborting the flow (LLR-003.1).
        FileExistsError: From ``_report_filename`` when all 99 same-second slots
            are taken — never a silent overwrite.

    Data Flow:
        - ``state`` → :func:`compose_flow_report` → ``reports/<ts>-report.md``.

    Dependencies:
        Uses:
            - compose_flow_report
            - report_service._report_filename / REPORTS_DIR_NAME (reuse, not fork)
        Used by:
            - flow_execution_service.run_flow (the ReportBlock branch)
    """
    clock = now_fn if now_fn is not None else _default_now
    generated_at = clock()
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    target = reports_dir / _report_filename(reports_dir, generated_at)
    target.write_text(compose_flow_report(state, generated_at), encoding="utf-8")
    return target
