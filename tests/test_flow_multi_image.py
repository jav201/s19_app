"""batch-70 — FB-P2 multi-image flow runs (engine layer, Inc-1).

Black-box ATs drive the shipped ``run_flow_over_variants`` surface and inspect
the :class:`FusedFlowRunResult`; white-box TCs pin the mechanism. Every project
lives under a real ``.s19tool/workarea/`` root because WRITE-OUT emits there.

Traceability (01-requirements.md §5.2):
  AT-205 V variants -> V executions   · TC-500 counting seams · TC-501 plan order
  AT-206 variant k aborts, k+1..V run · TC-502 isolation boundary
  AT-211 containment rejection is per-variant · TC-507 code · TC-508 census
  AT-210 unscoped run is unchanged    · TC-506 identity binding

RED pre-state (recorded §5.1): before Inc-1, ``run_flow_over_variants`` and
``FlowContext.variant`` do not exist, so every test here fails at import.
"""

from __future__ import annotations

import json
from pathlib import Path

from s19_app.tui.models import VariantDescriptor
from s19_app.tui.services.flow_execution_service import (
    _bound_source_ref,
    run_flow,
    run_flow_over_variants,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    WRITE_FMT_S19,
    Flow,
    FlowContext,
    FlowRunResult,
    FusedFlowRunResult,
    PatchBlock,
    SourceBlock,
    VariantRunOutcome,
)
from s19_app.tui.services.flow_persistence_service import REJECTING_CODES
from s19_app.tui.services.variant_execution_service import (
    MANIFEST_PATH_ESCAPE,
    SCOPE_ALL,
)
from s19_app.tui.workspace import build_variant_set

#: One data record at 0x1000 = 01 02 03 04 -> ranges [(0x1000, 0x1004)].
_S19_SRC = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_doc(entries: list[dict]) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _variants(project: Path, *names: str) -> list[VariantDescriptor]:
    return [
        VariantDescriptor(
            variant_id=name, path=project / f"{name}.s19", file_type=WRITE_FMT_S19
        )
        for name in names
    ]


class _CountingPlan:
    """A planned set that records how many descriptors were consumed.

    The AC-1 oracle. Counting CONSUMPTION is a structural measurement — unlike
    wall-clock or peak-memory, which batch-63 proved cannot distinguish
    cap-and-continue from cap-and-break.
    """

    def __init__(self, descriptors: list[VariantDescriptor]) -> None:
        self._descriptors = descriptors
        self.pulled = 0

    def __iter__(self):
        for descriptor in self._descriptors:
            self.pulled += 1
            yield descriptor


# ---------------------------------------------------------------------------
# AT-205 / TC-500 — V variants produce exactly V executions
# ---------------------------------------------------------------------------

def test_at205_v_variants_produce_v_executions(tmp_path: Path) -> None:
    """Three declared variants → the flow runs three times, once per image."""
    project = _make_project(
        tmp_path, {"a.s19": _S19_SRC, "b.s19": _S19_SRC, "c.s19": _S19_SRC}
    )
    plan = _CountingPlan(_variants(project, "a", "b", "c"))
    executed: list[str] = []

    def counting_run_one(flow: Flow, ctx: FlowContext) -> FlowRunResult:
        executed.append(ctx.variant.variant_id)
        return run_flow(flow, ctx)

    flow = Flow(name="f", blocks=[SourceBlock("ignored.s19", file_type=WRITE_FMT_S19)])
    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), plan=plan, run_one=counting_run_one
    )

    assert plan.pulled == 3, "the planned set must be consumed once per variant"
    assert executed == ["a", "b", "c"], "one execution per planned image, in plan order"
    assert len(fused.variant_outcomes) == 3
    assert fused.status == FLOW_STATUS_OK
    assert (fused.n_ok, fused.n_issues, fused.n_error) == (3, 0, 0)


def test_tc500_source_ref_is_overridden_per_variant_not_by_the_block(
    tmp_path: Path,
) -> None:
    """The SOURCE block's own ref is IGNORED under a variant scope (D-2).

    The block names a file that does not exist; every variant still loads,
    which is only possible if the variant's image replaced the block's ref —
    and the flow object must come out unmutated.
    """
    project = _make_project(tmp_path, {"a.s19": _S19_SRC, "b.s19": _S19_SRC})
    source = SourceBlock("does-not-exist.s19", file_type=WRITE_FMT_S19)
    flow = Flow(name="f", blocks=[source])

    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), plan=_variants(project, "a", "b")
    )

    assert [o.result.status for o in fused.variant_outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_OK,
    ]
    assert source.image_ref == "does-not-exist.s19", "the flow must not be mutated"
    summaries = [o.result.block_results[0].summary for o in fused.variant_outcomes]
    assert "loaded a.s19" in summaries[0] and "loaded b.s19" in summaries[1]


def test_tc501_plan_comes_from_the_projects_own_variant_machinery(
    tmp_path: Path,
) -> None:
    """D-1: the image set is derived from ``plan_variant_executions``, not a list.

    Driven end-to-end from ``build_variant_set`` so the reuse — not a parallel
    concept that could name images outside the project — is what is observed.
    """
    project = _make_project(
        tmp_path, {"a.s19": _S19_SRC, "b.s19": _S19_SRC, "c.s19": _S19_SRC}
    )
    variant_set = build_variant_set(
        "proj", [project / "a.s19", project / "b.s19", project / "c.s19"]
    )
    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])

    fused = run_flow_over_variants(
        flow, FlowContext(project_dir=project), variant_set, None, SCOPE_ALL
    )

    assert [o.variant_id for o in fused.variant_outcomes] == ["a", "b", "c"]
    assert len(fused.variant_outcomes) == len(variant_set.variants)


# ---------------------------------------------------------------------------
# AT-206 / TC-502 — one variant's abort does not stop the others (D-3)
# ---------------------------------------------------------------------------

def test_at206_aborting_variant_does_not_stop_the_remaining_ones(
    tmp_path: Path,
) -> None:
    """Variant *k* aborts; *k+1…V* still execute and carry their own statuses."""
    project = _make_project(tmp_path, {"a.s19": _S19_SRC, "c.s19": _S19_SRC})
    # "b" is declared but its image is absent — the SOURCE aborts that run only.
    plan = _variants(project, "a", "b", "c")
    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])

    fused = run_flow_over_variants(flow, FlowContext(project_dir=project), plan=plan)

    assert [o.variant_id for o in fused.variant_outcomes] == ["a", "b", "c"]
    assert [o.result.status for o in fused.variant_outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_ERROR,
        FLOW_STATUS_OK,
    ]
    assert fused.status == FLOW_STATUS_ERROR, "the roll-up takes the worst (D-5)"
    assert (fused.n_ok, fused.n_issues, fused.n_error) == (2, 0, 1)


def test_tc502_an_exception_escaping_run_flow_is_isolated_to_its_variant(
    tmp_path: Path,
) -> None:
    """The isolation boundary holds even if the executor breaks its no-raise contract."""
    project = _make_project(tmp_path, {"a.s19": _S19_SRC, "b.s19": _S19_SRC})

    def exploding_run_one(flow: Flow, ctx: FlowContext) -> FlowRunResult:
        if ctx.variant.variant_id == "a":
            raise RuntimeError("boom")
        return run_flow(flow, ctx)

    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])
    fused = run_flow_over_variants(
        flow,
        FlowContext(project_dir=project),
        plan=_variants(project, "a", "b"),
        run_one=exploding_run_one,
    )

    assert len(fused.variant_outcomes) == 2, "the planned set is never truncated"
    assert fused.variant_outcomes[0].result.status == FLOW_STATUS_ERROR
    assert "RuntimeError: boom" in fused.variant_outcomes[0].result.diagnostics[0]
    assert fused.variant_outcomes[1].result.status == FLOW_STATUS_OK


# ---------------------------------------------------------------------------
# AT-211 / TC-507 / TC-508 — a containment rejection fails ONE variant (AC-7)
# ---------------------------------------------------------------------------

def test_at211_containment_rejected_variant_fails_closed_alone(
    tmp_path: Path,
) -> None:
    """A variant pointing outside the project fails closed; the others run.

    This is the constraint the batch-69 spec declared mandatory in §7 and that
    no AC-1..AC-6 observed — D-3 (isolation) must not become a containment
    bypass, so the rejected variant must FAIL, not silently succeed.
    """
    project = _make_project(tmp_path, {"a.s19": _S19_SRC, "c.s19": _S19_SRC})
    outside = tmp_path / "outside.s19"
    outside.write_text(_S19_SRC, encoding="utf-8")
    plan = [
        _variants(project, "a")[0],
        VariantDescriptor("evil", outside, WRITE_FMT_S19),
        _variants(project, "c")[0],
    ]
    flow = Flow(name="f", blocks=[SourceBlock("x.s19", file_type=WRITE_FMT_S19)])

    fused = run_flow_over_variants(flow, FlowContext(project_dir=project), plan=plan)

    assert [o.variant_id for o in fused.variant_outcomes] == ["a", "evil", "c"]
    assert [o.result.status for o in fused.variant_outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_ERROR,
        FLOW_STATUS_OK,
    ]
    rejected = fused.variant_outcomes[1].result.block_results[0]
    assert rejected.status == BLOCK_STATUS_ERROR
    assert any(MANIFEST_PATH_ESCAPE in d for d in rejected.diagnostics), (
        "the rejection code must be recorded, not just the failure"
    )


def test_tc507_bound_source_ref_rejects_an_out_of_project_variant(
    tmp_path: Path,
) -> None:
    """White-box: the binding helper records exactly one rejection and returns None."""
    project = _make_project(tmp_path, {"a.s19": _S19_SRC})
    outside = tmp_path / "outside.s19"
    outside.write_text(_S19_SRC, encoding="utf-8")
    issues: list = []

    binding = _bound_source_ref(
        FlowContext(
            project_dir=project, variant=VariantDescriptor("evil", outside, WRITE_FMT_S19)
        ),
        SourceBlock("x.s19", file_type=WRITE_FMT_S19),
        issues,
    )

    assert binding is None
    assert [issue.code for issue in issues] == [MANIFEST_PATH_ESCAPE]


def test_tc508_the_variant_rejection_code_is_under_the_existing_census() -> None:
    """AC-7 consumes the shipped C-31 census rather than building a new oracle.

    If the variant path ever rejects with a code outside ``REJECTING_CODES``,
    the reject-arm battery stops covering it silently — this pins that it does not.
    """
    assert MANIFEST_PATH_ESCAPE in REJECTING_CODES


# ---------------------------------------------------------------------------
# AT-210 / TC-506 — the new dimension is ADDITIVE (AC-6)
# ---------------------------------------------------------------------------

def test_tc506_unscoped_binding_is_the_identity(tmp_path: Path) -> None:
    """``ctx.variant is None`` returns the block's own ref and type, untouched."""
    project = _make_project(tmp_path, {"a.s19": _S19_SRC})
    block = SourceBlock("a.s19", file_type=WRITE_FMT_S19)

    assert _bound_source_ref(FlowContext(project_dir=project), block, []) == (
        "a.s19",
        WRITE_FMT_S19,
    )


def test_at210_unscoped_run_is_unchanged_by_the_variant_dimension(
    tmp_path: Path,
) -> None:
    """An unscoped run still produces today's single-image result.

    The byte-level half of AC-6 is carried by ``test_at210_golden`` in
    ``test_flow_report_fusion.py`` (the composer for the single-image path is a
    different module and is not edited at all).
    """
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(tmp_path, {"a.s19": _S19_SRC, "p.json": patch})
    flow = Flow(
        name="f",
        blocks=[SourceBlock("a.s19", file_type=WRITE_FMT_S19), PatchBlock("p.json")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    assert [br.summary for br in result.block_results] == [
        "loaded a.s19 (1 ranges)",
        "applied 1 entry",
    ]


def test_tc501b_model_containers_are_well_formed() -> None:
    """The fused containers exist with the fields every consumer reads."""
    fused = FusedFlowRunResult(status=FLOW_STATUS_OK)
    assert fused.variant_outcomes == [] and fused.n_ok == 0
    outcome = VariantRunOutcome("a", FlowRunResult(status=FLOW_STATUS_OK))
    assert outcome.variant_id == "a"
    assert "variant" in FlowContext.__dataclass_fields__
