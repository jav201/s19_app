#!/usr/bin/env python3
"""FB-P1b prototype — flow-run report GENERATION (compose-from-FlowRunResult).

Standalone, dependency-free prototype of the report a `ReportBlock` will generate
when `run_flow` reaches it (batch-53 shipped the block as a no-op; FB-P1b makes it
produce content). Report generation is DETERMINISTIC — it composes markdown from
the run state already assembled in `FlowRunResult` (per-block ledger, findings,
image footprint, written files). No model/LLM judgment; code answers (rule 5).

Design (operator-confirmed at kickoff):
- **Explicit trigger:** a report is generated ONLY when the flow contains a
  `ReportBlock` (honors the batch-53 shipped model). The block is POSITIONAL — it
  reports the state of the run UP TO its position (blocks executed before it +
  the current threaded image footprint). A flow that puts REPORT last (the
  typical shape) therefore captures the whole pipeline.
- **Where:** written into the project `reports/` dir under the SAME
  `<ts>-report.md` convention the project reports use, so the existing
  `list_project_reports` + `ReportViewerScreen` surface it with no new viewer.
- **Security (C-17):** every file-derived string (block summaries, finding
  messages, written paths, the flow name) is markdown-neutralised via `_md_safe`
  before it enters the report — a hostile `change_doc_ref` cannot inject a table
  break, a heading, or a link into the rendered Markdown widget.

Run:  python prototypes/fb_p1b_report.prototype.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Minimal stand-ins for the real flow_model types (prototype-local).
# --------------------------------------------------------------------------- #

STATUS_OK = "ok"
STATUS_NOTICES = "notices"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"

FLOW_CLEAN = "clean"
FLOW_ISSUES = "completed-with-issues"
FLOW_FAILED = "failed"


@dataclass
class Finding:
    message: str
    severity: str = "warning"  # warning | error


@dataclass
class BlockResult:
    index: int
    kind: str
    status: str
    summary: str = ""
    findings: List[Finding] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)


@dataclass
class FlowRunState:
    """The slice of run state a positional ReportBlock composes from."""
    flow_name: str
    block_results: List[BlockResult]
    image_ranges: List[Tuple[int, int]]
    pre_crc_ranges: List[Tuple[int, int]] = field(default_factory=list)
    written_paths: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Markdown-safety (C-17) — neutralise file-derived text before it enters markdown.
# --------------------------------------------------------------------------- #

def _md_safe(value: object) -> str:
    """Render `value` inert inside markdown (esp. tables + inline).

    Escapes the markdown-significant characters a hostile file-derived string
    could use to break a table row, open a heading/list, or forge a link/emphasis,
    and strips control chars + collapses newlines (a report cell is one line).
    """
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch if ch >= " " else " " for ch in text)  # drop control bytes
    # Escape markdown structure. Backslash FIRST so we don't double-escape.
    for ch in ("\\", "`", "|", "*", "_", "[", "]", "<", ">", "#"):
        text = text.replace(ch, "\\" + ch)
    return text.strip() or "(empty)"


def _fmt_ranges(ranges: Sequence[Tuple[int, int]]) -> str:
    if not ranges:
        return "(none)"
    parts = [f"0x{lo:08X}–0x{hi:08X}" for lo, hi in ranges]
    total = sum(hi - lo + 1 for lo, hi in ranges)
    return f"{', '.join(parts)}  ({total:,} bytes)"


_STATUS_GLYPH = {STATUS_OK: "●", STATUS_NOTICES: "◈",
                 STATUS_ERROR: "✖", STATUS_SKIPPED: "○"}


def _provisional_status(block_results: Sequence[BlockResult]) -> str:
    """Status of the run SO FAR (the report is positional; the flow-level rollup
    is only final after the last block — mirror the run_flow three-way rule)."""
    if any(b.status == STATUS_ERROR and b.summary == "error" for b in block_results):
        return FLOW_FAILED
    if any(b.status in {STATUS_NOTICES, STATUS_ERROR} or b.findings
           for b in block_results):
        return FLOW_ISSUES
    return FLOW_CLEAN


# --------------------------------------------------------------------------- #
# The composer — the FB-P1b deliverable (a pure function).
# --------------------------------------------------------------------------- #

def compose_flow_report(state: FlowRunState, timestamp: str) -> str:
    """Compose the markdown flow-run report from `state` (pure, deterministic)."""
    lines: List[str] = []
    status = _provisional_status(state.block_results)
    status_label = {FLOW_CLEAN: "CLEAN", FLOW_ISSUES: "COMPLETED WITH ISSUES",
                    FLOW_FAILED: "FAILED"}[status]

    lines.append(f"# Flow report — {_md_safe(state.flow_name)}")
    lines.append("")
    lines.append(f"- **Generated:** {timestamp}")
    lines.append(f"- **Status:** {status_label}")
    lines.append(f"- **Blocks reported:** {len(state.block_results)} "
                 "(up to the report block)")
    lines.append("")

    # Pipeline ledger.
    lines.append("## Pipeline ledger")
    lines.append("")
    lines.append("| # | Block | Status | Summary |")
    lines.append("|---|-------|--------|---------|")
    for br in state.block_results:
        glyph = _STATUS_GLYPH.get(br.status, "·")
        lines.append(
            f"| {br.index + 1} | {_md_safe(br.kind.upper())} | "
            f"{glyph} {_md_safe(br.status)} | {_md_safe(br.summary)} |"
        )
    lines.append("")

    # Findings (per block, markup-safe).
    findings = [(br, f) for br in state.block_results for f in br.findings]
    if findings:
        lines.append("## Findings")
        lines.append("")
        for br, f in findings:
            lines.append(f"- **[{_md_safe(br.kind.upper())} #{br.index + 1}]** "
                         f"({_md_safe(f.severity)}) {_md_safe(f.message)}")
        lines.append("")

    # Image footprint (before/after CRC growth is the FB signature).
    lines.append("## Image footprint")
    lines.append("")
    if state.pre_crc_ranges:
        lines.append(f"- **Before CRC:** {_fmt_ranges(state.pre_crc_ranges)}")
    lines.append(f"- **Final:** {_fmt_ranges(state.image_ranges)}")
    lines.append("")

    # Written files.
    lines.append("## Written files")
    lines.append("")
    if state.written_paths:
        for p in state.written_paths:
            lines.append(f"- `{_md_safe(p)}`")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by the s19_app Flow Builder (FB-P1b).*")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Demo — a realistic LOAD -> PATCH -> CRC -> WRITE-OUT -> REPORT run,
# including a HOSTILE change_doc_ref finding to prove markup-safety.
# --------------------------------------------------------------------------- #

def _sample_state() -> FlowRunState:
    hostile = "calib[bad].json | # INJECTED `code` <script>"
    return FlowRunState(
        flow_name="nightly-release",
        block_results=[
            BlockResult(0, "source", STATUS_OK, "loaded prg.s19 (2 ranges, 8,192 bytes)"),
            BlockResult(1, "patch", STATUS_NOTICES,
                        f"applied {hostile}",
                        findings=[Finding(f"unresolved region in {hostile}", "warning")]),
            BlockResult(2, "crc", STATUS_OK, "injected 1 CRC over 0x8000–0x8FFF"),
            BlockResult(3, "write-out", STATUS_OK, "wrote prg_patched.s19 (hex)"),
        ],
        image_ranges=[(0x8000, 0x9FFF)],
        pre_crc_ranges=[(0x8000, 0x8FFF)],
        written_paths=["prg_patched.s19"],
    )


if __name__ == "__main__":
    report = compose_flow_report(_sample_state(), "2026-07-24 22:40:00 UTC")
    print(report)
    # Sanity: the hostile ref injected NO live markdown structure.
    assert "| # INJECTED" not in report  # no unescaped table break
    assert "`code`" not in report        # no unescaped code span
    print("\n✓ markup-safety self-check passed (hostile ref rendered inert)")
