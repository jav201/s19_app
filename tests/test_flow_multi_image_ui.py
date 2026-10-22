"""batch-70 — FB-P2 scope selector + fused rendering (Inc-4), plus D-4 on disk.

Traceability (01-requirements.md §5.2):
  LLR-104.6 the scope is selectable and wired through the ONE run call site
  D-4       a fused run emits ONE report file, never one per variant

The D-4 arm is an artifact-on-disk acceptance: it counts the files in
``reports/`` after a fused run, because "one document" is a claim about the
filesystem and only the filesystem can settle it.

Batch-91 contract adoption (HLR-122):
# TC-642 — this module pins the flow execution and multi-image UI arms (LLR-122.5).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import VariantDescriptor
from s19_app.tui.flow_screens import FlowBuilderPanel
from s19_app.tui.services.flow_execution_service import run_flow, run_flow_over_variants
from s19_app.tui.services.flow_model import (
    FLOW_SCOPE_SINGLE,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    WRITE_FMT_S19,
    Flow,
    FlowContext,
    FlowRunResult,
    FusedFlowRunResult,
    ReportBlock,
    SourceBlock,
    VariantRunOutcome,
)
from s19_app.tui.services.variant_execution_service import (
    SCOPE_ASSIGNMENTS,
    read_project_manifest,
)
from s19_app.tui.workspace import build_variant_set, validate_project_files

_S19_SRC = "S107100001020304DE\nS9030000FC\n"


def _project(tmp_path: Path, *variants: str) -> Path:
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True, exist_ok=True)
    for name in variants:
        (project / f"{name}.s19").write_text(_S19_SRC, encoding="utf-8")
    return project


def _plan(project: Path, *names: str) -> list[VariantDescriptor]:
    return [
        VariantDescriptor(name, project / f"{name}.s19", WRITE_FMT_S19)
        for name in names
    ]


# ---------------------------------------------------------------------------
# D-4 — ONE fused report file, not one per variant
# ---------------------------------------------------------------------------

def test_d4_a_fused_run_writes_exactly_one_report_file(tmp_path: Path) -> None:
    """Three variants + a REPORT block → one file in ``reports/``.

    Without the deferral this writes three, which is the manual collation FB-P2
    exists to remove — and it would pass every composer-level test, because the
    defect is a count of FILES.
    """
    project = _project(tmp_path, "a", "b", "c")
    flow = Flow(
        name="f",
        blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19), ReportBlock()],
    )

    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), plan=_plan(project, "a", "b", "c")
    )

    reports = sorted((project / "reports").iterdir())
    assert len(reports) == 1, f"expected ONE fused report, found {len(reports)}"
    assert fused.report_path == reports[0]
    body = reports[0].read_text(encoding="utf-8")
    assert [line for line in body.splitlines() if line.startswith("### ")] == [
        "### a", "### b", "### c",
    ]


def test_d4_the_deferred_report_block_still_appears_in_each_variants_ledger(
    tmp_path: Path,
) -> None:
    """Deferring must not HIDE the block — a silent skip is its own defect."""
    project = _project(tmp_path, "a", "b")
    flow = Flow(
        name="f",
        blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19), ReportBlock()],
    )

    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), plan=_plan(project, "a", "b")
    )

    for outcome in fused.variant_outcomes:
        assert len(outcome.result.block_results) == len(flow.blocks)
        assert outcome.result.block_results[1].summary == "deferred to the fused report"


def test_d4_a_flow_without_a_report_block_writes_no_report(tmp_path: Path) -> None:
    """The negative control: fusion does not invent an output nobody asked for."""
    project = _project(tmp_path, "a", "b")
    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])

    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), plan=_plan(project, "a", "b")
    )

    assert fused.report_path is None
    assert not (project / "reports").exists()


def test_d4_an_unscoped_run_still_writes_its_own_report(tmp_path: Path) -> None:
    """AC-6: the deferral is opt-in, so the single-image path is untouched."""
    project = _project(tmp_path, "a")
    flow = Flow(
        name="f",
        blocks=[SourceBlock("a.s19", file_type=WRITE_FMT_S19), ReportBlock()],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    reports = list((project / "reports").iterdir())
    assert len(reports) == 1
    body = reports[0].read_text(encoding="utf-8")
    assert body.startswith("# Flow report —"), "not the fused document"
    assert "deferred" not in body


# ---------------------------------------------------------------------------
# LLR-104.6 — the scope selector
# ---------------------------------------------------------------------------

# batch-97 Inc-5 (D8, LLR-146.12, named supersession): the Builder composes no
# scope selector and Run always requests FLOW_SCOPE_SINGLE — multi-variant runs
# live in Flow Execution, one chain per variant. Retired here:
# ``test_llr1046_scope_options_cover_every_declared_scope`` (``_SCOPE_OPTIONS``
# left the panel), ``test_llr1046_selecting_all_variants_runs_the_fused_path``
# and ``test_llr1046_a_variant_scope_without_variants_degrades_to_an_error_card``
# (both picked a variant scope on ``#flow_scope``); their successor is
# TC-B97-50 (``tests/test_b97_flow_builder.py``). The service tests (D-4, the
# assignments plan) and the retained ``render_fused_result`` test stay.


def test_llr1046_run_requested_defaults_to_the_single_image_scope() -> None:
    """A caller that predates the scope still gets the unchanged path (AC-6)."""
    message = FlowBuilderPanel.RunRequested(Flow(name="f"))
    assert message.scope == FLOW_SCOPE_SINGLE


async def _run_scoped(app: S19TuiApp, pilot, project: Path, blocks) -> str:
    """Compose ``blocks`` in a project that declares variants, press the REAL
    Run button, read the pane.

    Drives the shipped surface end to end — Run → ``RunRequested`` →
    ``S19TuiApp.on_flow_builder_panel_run_requested`` → engine → repaint — so
    what is observed is the wiring, not a hand-built message.
    """
    app.current_project_dir = project
    _data_files, _a2l, _error = validate_project_files(project)
    app._variant_set = build_variant_set("proj", _data_files)
    await pilot.press("8")
    await pilot.pause()
    panel = app.query_one("#flow_panel", FlowBuilderPanel)
    panel._blocks = list(blocks)
    app.query_one("#flow_run", Button).press()  # the real Run button
    await pilot.pause()
    await pilot.pause()
    return "\n".join(
        node.render().plain for node in app.query("#flow_result Static")
    )


def test_llr1046_the_assignments_scope_narrows_the_planned_set(tmp_path: Path) -> None:
    """The third scope option is not decorative — it must plan fewer variants.

    Shipping a selectable scope with no test would let "Assigned variants" run
    over ALL of them, which reads as working right up until the operator relies
    on it.
    """
    project = _project(tmp_path, "a", "b", "c")
    (project / "project.json").write_text(
        json.dumps({"schema_version": 1, "assignments": {"b": ["p.json"]}}),
        encoding="utf-8",
    )
    data_files, _a2l, _error = validate_project_files(project)
    variant_set = build_variant_set("proj", data_files)
    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])

    fused = run_flow_over_variants(
        flow,
        FlowContext(project_dir=project),
        variant_set,
        read_project_manifest(project),
        SCOPE_ASSIGNMENTS,
    )

    assert [o.variant_id for o in fused.variant_outcomes] == ["b"], (
        "only the assigned variant is planned"
    )
    assert len(variant_set.variants) == 3, "while three are declared"


def test_llr1046_this_image_still_takes_the_single_image_path(tmp_path: Path) -> None:
    """Run takes the single-image path, never the fused renderer (AC-6;
    batch-97 LLR-146.12 rewrote it without the retired scope select)."""
    project = _project(tmp_path, "a")
    blocks = [SourceBlock("a.s19", file_type=WRITE_FMT_S19)]

    async def _drive() -> str:
        app = S19TuiApp()
        async with app.run_test() as pilot:
            return await _run_scoped(app, pilot, project, blocks)

    rendered = asyncio.run(_drive())

    assert "CLEAN" in rendered
    assert "variant(s):" not in rendered, "the single-image pane gains no fused line"
    assert "loaded a.s19" in rendered


def test_llr1046_fused_result_renders_every_variant_and_the_inverted_counts(
    tmp_path: Path,
) -> None:
    """The panel paints one node per variant plus the counts that invert D-5."""
    fused = FusedFlowRunResult(status=FLOW_STATUS_ERROR)
    fused.variant_outcomes = [
        VariantRunOutcome("a", FlowRunResult(status=FLOW_STATUS_OK)),
        VariantRunOutcome("ev|il", FlowRunResult(status=FLOW_STATUS_ERROR)),
    ]
    fused.n_ok, fused.n_error = 1, 1
    fused.report_path = tmp_path / "reports" / "r.md"

    async def _drive() -> str:
        app = S19TuiApp()
        async with app.run_test() as pilot:
            await pilot.press("8")
            await pilot.pause()
            app.query_one("#flow_panel", FlowBuilderPanel).render_fused_result(fused)
            await pilot.pause()
            return "\n".join(
                node.render().plain for node in app.query("#flow_result Static")
            )

    rendered = asyncio.run(_drive())

    assert "FAILED" in rendered
    assert "2 variant(s): 1 ok / 0 issues / 1 error" in rendered
    assert "a  —  ok" in rendered
    assert "ev|il" in rendered, "every variant is painted, hostile id included"
    assert "fused report:" in rendered
