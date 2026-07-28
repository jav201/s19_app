"""batch-70 — FB-P2 fused multi-image report (Inc-2 + Inc-3).

Traceability (01-requirements.md §5.2):
  AT-207 exactly one section per variant, id escaped · TC-503 projection
  AT-208 roll-up is the worst; counts invert it     · TC-504 rollup arms
  AT-209 every variant represented; each cut named; the PRODUCER is bounded
                                                    · TC-505 cap arithmetic
  AT-210 the single-image composer is untouched (AC-6, structural)

The AC-5 oracle is a **counting sequence**: it records how many findings the
composer actually FORMATTED. Wall-clock and peak-memory were ruled out at
batch-63 — neither can distinguish cap-and-continue from cap-and-break.

RED pre-state (recorded §5.1): before Inc-2, ``flow_fused_report_service`` does
not exist. The bound's own counterfactual is recorded in 04-validation.md — the
caps reverted on a COPY of the fixed tree, which is the only form that fails on
its ASSERTION rather than on an import error.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List

from s19_app.tui.services import flow_report_service
from s19_app.tui.services.flow_fused_report_service import (
    MAX_FUSED_FINDINGS_PER_VARIANT,
    MAX_FUSED_LEDGER_ROWS_PER_VARIANT,
    build_fused_report_state,
    compose_fused_flow_report,
    write_fused_flow_report,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    BlockResult,
    Finding,
    FlowRunResult,
    FusedFlowRunResult,
    VariantRunOutcome,
)

_AT = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


class _CountingFindings(list):
    """A findings list that records how many entries were actually consumed.

    ``len()`` stays O(1) (inherited), so the composer can still compute a drop
    count without traversing — which is exactly the distinction being asserted:
    a bounded producer FORMATS ``cap`` entries while still REPORTING ``N``.
    """

    def __init__(self, items: List[Finding]) -> None:
        super().__init__(items)
        self.consumed = 0

    def __iter__(self) -> Iterator[Finding]:
        for item in super().__iter__():
            self.consumed += 1
            yield item


def _block(index: int, status: str = BLOCK_STATUS_OK, findings=None) -> BlockResult:
    br = BlockResult(index, "source", status, f"summary {index}")
    if findings is not None:
        br.findings = findings
    return br


def _outcome(variant_id: str, status: str, blocks=None) -> VariantRunOutcome:
    result = FlowRunResult(status=status)
    result.block_results = list(blocks or [_block(0)])
    result.image_ranges = [(0x1000, 0x1004)]
    return VariantRunOutcome(variant_id, result)


def _fused(*outcomes: VariantRunOutcome) -> FusedFlowRunResult:
    fused = FusedFlowRunResult(status=FLOW_STATUS_OK)
    fused.variant_outcomes = list(outcomes)
    fused.n_ok = sum(1 for o in outcomes if o.result.status == FLOW_STATUS_OK)
    fused.n_issues = sum(1 for o in outcomes if o.result.status == FLOW_STATUS_ISSUES)
    fused.n_error = sum(1 for o in outcomes if o.result.status == FLOW_STATUS_ERROR)
    if fused.n_error:
        fused.status = FLOW_STATUS_ERROR
    elif fused.n_issues:
        fused.status = FLOW_STATUS_ISSUES
    return fused


# ---------------------------------------------------------------------------
# AT-207 / TC-503 — exactly one section per executed variant, id escaped (AC-3)
# ---------------------------------------------------------------------------

def test_at207_exactly_one_section_per_executed_variant() -> None:
    fused = _fused(
        _outcome("a", FLOW_STATUS_OK),
        _outcome("b", FLOW_STATUS_ISSUES),
        _outcome("c", FLOW_STATUS_ERROR),
    )

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    headings = [line for line in doc.splitlines() if line.startswith("### ")]
    assert headings == ["### a", "### b", "### c"], (
        "one detail section per variant, in plan order"
    )
    assert doc.count("## Variant summary") == 1
    for variant_id in ("a", "b", "c"):
        assert f"| {variant_id} |" in doc, "and one always-emitted summary row"


def test_at207_variant_id_with_markdown_metacharacters_renders_escaped() -> None:
    """``variant_id`` is file-derived, so it enters through the md_safe path (D-6)."""
    fused = _fused(_outcome("ev|il`x", FLOW_STATUS_OK))

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "### ev\\|il" in doc, "the pipe must not break out into the table grammar"
    assert "| ev\\|il" in doc
    assert "ev|il" not in doc, "no unescaped occurrence may survive anywhere"


def test_tc503_state_projection_preserves_order_and_copies_the_counts() -> None:
    fused = _fused(_outcome("a", FLOW_STATUS_OK), _outcome("b", FLOW_STATUS_ERROR))

    state = build_fused_report_state("flow-name", fused, Path("/proj"))

    assert [s.variant_id for s in state.sections] == ["a", "b"]
    assert (state.n_ok, state.n_issues, state.n_error) == (1, 0, 1)
    assert state.status == fused.status, "the report never re-derives the roll-up"


# ---------------------------------------------------------------------------
# AT-208 / TC-504 — the roll-up is the worst AND it is invertible (AC-4)
# ---------------------------------------------------------------------------

def test_at208_rolled_up_status_is_the_worst_and_counts_sum_to_executed() -> None:
    fused = _fused(
        _outcome("a", FLOW_STATUS_OK),
        _outcome("b", FLOW_STATUS_ISSUES),
        _outcome("c", FLOW_STATUS_ERROR),
        _outcome("d", FLOW_STATUS_OK),
    )

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "- **Status:** FAILED" in doc.splitlines()[3], "any error wins the roll-up"
    assert "- **Variants executed:** 4" in doc
    assert "- **Outcome counts:** 2 ok / 1 issues / 1 error" in doc
    assert fused.n_ok + fused.n_issues + fused.n_error == len(fused.variant_outcomes)


def test_tc504_issues_wins_only_when_no_variant_errored() -> None:
    fused = _fused(_outcome("a", FLOW_STATUS_OK), _outcome("b", FLOW_STATUS_ISSUES))

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "- **Status:** COMPLETED WITH ISSUES" in doc
    assert "- **Outcome counts:** 1 ok / 1 issues / 0 error" in doc


def test_tc504b_all_clean_rolls_up_clean() -> None:
    fused = _fused(_outcome("a", FLOW_STATUS_OK), _outcome("b", FLOW_STATUS_OK))

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "- **Status:** CLEAN" in doc
    assert "- **Outcome counts:** 2 ok / 0 issues / 0 error" in doc


# ---------------------------------------------------------------------------
# AT-209 / TC-505 — the bound is per variant and charged in the PRODUCER (AC-5)
# ---------------------------------------------------------------------------

def test_at209_every_variant_survives_and_each_cut_names_its_dropped_count() -> None:
    """V variants each over the cap: all V present, every cut named, work bounded.

    The three assertions are one criterion: a bound that keeps the document
    small by dropping whole variants, or by dropping them silently, or by
    formatting everything and then truncating, each fails one of them.
    """
    over = MAX_FUSED_FINDINGS_PER_VARIANT + 25
    counters = {}
    outcomes = []
    for variant_id in ("a", "b", "c"):
        findings = _CountingFindings(
            [Finding("warn", f"{variant_id} finding {i}") for i in range(over)]
        )
        counters[variant_id] = findings
        outcomes.append(
            _outcome(variant_id, FLOW_STATUS_ISSUES, [_block(0, BLOCK_STATUS_NOTICES, findings)])
        )
    fused = _fused(*outcomes)

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    # (1) every variant is still represented
    assert [line for line in doc.splitlines() if line.startswith("### ")] == [
        "### a", "### b", "### c",
    ]
    # (2) every cut section names its variant and its dropped count
    for variant_id in ("a", "b", "c"):
        assert (
            f"> **Cut in `{variant_id}`:** findings: 25 omitted "
            f"(cap {MAX_FUSED_FINDINGS_PER_VARIANT} per variant)."
        ) in doc, f"the cut in {variant_id} must be named with its count"
    # (3) THE bound: the producer FORMATTED at most the cap per variant. An
    #     unbounded composer consumes all `over` entries and this goes RED.
    for variant_id, findings in counters.items():
        assert findings.consumed <= MAX_FUSED_FINDINGS_PER_VARIANT, (
            f"variant {variant_id} formatted {findings.consumed} findings; the "
            f"cap is {MAX_FUSED_FINDINGS_PER_VARIANT} — the cost is charged in "
            "the producer, not at the writer"
        )


def test_at209_one_pathological_variant_does_not_evict_the_others() -> None:
    """The cap is per variant, so a huge variant cannot starve a small one."""
    huge = _CountingFindings(
        [Finding("warn", f"huge {i}") for i in range(MAX_FUSED_FINDINGS_PER_VARIANT * 20)]
    )
    small = [Finding("warn", "small 0")]
    fused = _fused(
        _outcome("huge", FLOW_STATUS_ISSUES, [_block(0, BLOCK_STATUS_NOTICES, huge)]),
        _outcome("small", FLOW_STATUS_ISSUES, [_block(0, BLOCK_STATUS_NOTICES, small)]),
    )

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "small 0" in doc, "the small variant's evidence must survive intact"
    assert "> **Cut in `small`" not in doc, "and must not be cut at all"
    assert huge.consumed <= MAX_FUSED_FINDINGS_PER_VARIANT


def test_tc505_ledger_rows_are_capped_and_the_drop_count_is_named() -> None:
    over = MAX_FUSED_LEDGER_ROWS_PER_VARIANT + 7
    blocks = [_block(i) for i in range(over)]
    fused = _fused(_outcome("a", FLOW_STATUS_OK, blocks))

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    # A ledger row is the only line carrying a block summary; the summary-table
    # rows above it carry counts, not summaries.
    rendered = [line for line in doc.splitlines() if "| summary " in line]
    assert len(rendered) == MAX_FUSED_LEDGER_ROWS_PER_VARIANT
    assert rendered[0].startswith("| 1 |") and rendered[-1].startswith(
        f"| {MAX_FUSED_LEDGER_ROWS_PER_VARIANT} |"
    ), "the kept rows are the FIRST cap rows, contiguously"
    assert (
        f"ledger rows: 7 omitted (cap {MAX_FUSED_LEDGER_ROWS_PER_VARIANT} per variant)"
    ) in doc


def test_tc505b_a_variant_under_the_cap_carries_no_cut_notice() -> None:
    """The negative control — the notice must not fire when nothing was cut."""
    findings = [Finding("warn", f"f{i}") for i in range(3)]
    fused = _fused(
        _outcome("a", FLOW_STATUS_ISSUES, [_block(0, BLOCK_STATUS_NOTICES, findings)])
    )

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    assert "> **Cut in" not in doc
    assert "f2" in doc


def test_tc505c_diagnostics_share_the_variant_budget_with_findings() -> None:
    """A block's diagnostics are evidence too and are charged to the same cap."""
    block = _block(0, BLOCK_STATUS_ERROR)
    block.diagnostics = [f"diag {i}" for i in range(MAX_FUSED_FINDINGS_PER_VARIANT + 4)]
    fused = _fused(_outcome("a", FLOW_STATUS_ERROR, [block]))

    doc = compose_fused_flow_report(build_fused_report_state("f", fused), _AT)

    emitted = sum(1 for line in doc.splitlines() if "(diagnostic)" in line)
    assert emitted == MAX_FUSED_FINDINGS_PER_VARIANT
    assert "findings: 4 omitted" in doc


# ---------------------------------------------------------------------------
# AT-210 — AC-6 is structural: the single-image composer is not edited
# ---------------------------------------------------------------------------

def test_at210_single_image_composer_is_untouched_by_the_fused_path() -> None:
    """The fused document is composed by a DIFFERENT function.

    AC-6 asks for byte-identity with today's single-image output. The strongest
    available form of that is structural: ``compose_flow_report`` has no variant
    parameter and no branch on one, so a fused run cannot change what an
    unscoped run emits.
    """
    signature = inspect.signature(flow_report_service.compose_flow_report)
    assert list(signature.parameters) == ["state", "generated_at"]
    source = inspect.getsource(flow_report_service.compose_flow_report)
    assert "variant" not in source
    assert "variant" not in inspect.getsource(flow_report_service.FlowReportState)


# ---------------------------------------------------------------------------
# D-8 — the fused report is written through the shipped naming seam
# ---------------------------------------------------------------------------

def test_tc503b_fused_report_is_written_under_the_shipped_report_name(
    tmp_path: Path,
) -> None:
    from s19_app.tui.services.report_service import REPORT_FILENAME_REGEX

    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    state = build_fused_report_state("f", _fused(_outcome("a", FLOW_STATUS_OK)), project)

    path = write_fused_flow_report(state, project, now_fn=lambda: _AT)

    assert path.parent.name == "reports"
    assert REPORT_FILENAME_REGEX.match(path.name), (
        "the fused report must stay visible to the shipped viewer (D-8)"
    )
    assert "# Fused flow report" in path.read_text(encoding="utf-8")
