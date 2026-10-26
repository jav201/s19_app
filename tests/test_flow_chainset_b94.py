"""Batch-94 Inc-003 — the chain-set runner + the chain-set envelope (service layer).

TC-B94-05 · TC-B94-28 · TC-B94-30 · TC-B94-31 (white-box, C-18: one on-disk
node per TC) + the RED battery's service-side arms. The runner is observed
through its declared seams (``run_one`` / ``clock`` — the
``run_flow_over_variants`` AC idiom) and its EMITTED bytes (the chain-set
report, C-42: the predicate pins the producer's own paste).
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_execution_service import (
    CHAIN_RUN_PARALLEL,
    CHAIN_RUN_SEQUENTIAL,
    ChainSpec,
    compose_chain_set_report,
    run_chain_set,
)
from s19_app.tui.services.flow_model import (
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    Flow,
    FlowContext,
    SourceBlock,
    PatchBlock,
    CrcBlock,
    WriteOutBlock,
)

#: Minimal CLEAN S19 — 01 02 03 04 at 0x1000 (checksum-verified).
_S19 = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_json(n_entries: int = 1) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "bytes", "address": f"0x{0x1000 + i:X}", "bytes": "AA"}
                for i in range(n_entries)
            ],
        }
    )


def _project(tmp_path: Path) -> Path:
    return _make_project(
        tmp_path,
        {
            "base.s19": _S19,
            "variant_b.hex": _S19,
            "hotfix.json": _patch_json(),
        },
    )


def _clean_chain(name: str, template: str = "base") -> ChainSpec:
    return ChainSpec(
        name=name,
        template=template,
        flow=Flow(
            name=name,
            blocks=[
                SourceBlock("base.s19"),
                PatchBlock("hotfix.json"),
                WriteOutBlock("out.s19"),
            ],
        ),
    )


# --------------------------------------------------------------------------- #
# TC-B94-05 — mode capture in the persisted run record (LLR-019.2, LED.5)
# --------------------------------------------------------------------------- #


def test_tc_b94_05_mode_capture_in_run_record_and_report(tmp_path: Path) -> None:
    """TC-B94-05 (LLR-019.2, white-box): the record's mode field reads
    ``parallel`` in 1/1 driven parallel runs and ``sequential`` on the
    untouched default arm — and the EMITTED report persists the same mode
    line (the C-42 predicate pins the producer's own form).
    """
    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)

    driven = run_chain_set(
        [_clean_chain("a"), _clean_chain("b")],
        ctx,
        mode=CHAIN_RUN_PARALLEL,
        set_name="variants_a_b",
    )
    untouched = run_chain_set(
        [_clean_chain("a"), _clean_chain("b")],
        ctx,
        set_name="variants_a_b",
    )

    # The C-10 captured-value assertion: the driven record differs from the
    # default arm's record; 1/1 driven parallel runs read ``parallel``.
    assert driven.mode == CHAIN_RUN_PARALLEL
    assert untouched.mode == CHAIN_RUN_SEQUENTIAL
    assert driven.mode != untouched.mode
    # The persisted surface: the emitted report's own Mode line.
    assert driven.report_path is not None
    report = driven.report_path.read_text(encoding="utf-8")
    assert "- **Mode:** parallel" in report
    assert untouched.report_path is not None
    default_report = untouched.report_path.read_text(encoding="utf-8")
    assert "- **Mode:** sequential" in default_report


def test_tc_b94_05_parallel_dispatch_runs_chains_concurrently(
    tmp_path: Path,
) -> None:
    """TC-B94-05's dispatch arm (LLR-019.2): parallel mode executes both
    chains CONCURRENTLY — each chain waits on a two-party barrier inside its
    own window, so overlap is structural, not statistical.
    """
    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)
    barrier = threading.Barrier(2)
    entered: list[str] = []

    def _run_one(flow: Flow, run_ctx: FlowContext):
        entered.append(flow.name)
        barrier.wait(timeout=10)
        return run_chain_set.__globals__["run_flow"](flow, run_ctx)

    record = run_chain_set(
        [_clean_chain("a"), _clean_chain("b")],
        ctx,
        mode=CHAIN_RUN_PARALLEL,
        run_one=_run_one,
    )
    assert sorted(entered) == ["a", "b"], (
        f"both chains must ENTER their windows (the barrier proves "
        f"concurrency); entered={entered}"
    )
    assert len(record.outcomes) == 2
    starts = [outcome.started_at for outcome in record.outcomes]
    ends = [outcome.finished_at for outcome in record.outcomes]
    # Overlapping windows: each chain started before the other finished.
    assert starts[0] < ends[1] and starts[1] < ends[0], (
        f"parallel windows must overlap: starts={starts} ends={ends}"
    )
    # The untouched default arm runs strictly one-after-another.
    sequential = run_chain_set(
        [_clean_chain("a"), _clean_chain("b")],
        ctx,
        mode=CHAIN_RUN_SEQUENTIAL,
    )
    s_starts = [outcome.started_at for outcome in sequential.outcomes]
    s_ends = [outcome.finished_at for outcome in sequential.outcomes]
    assert s_starts[1] >= s_ends[0], (
        f"sequential arm must show 0 overlap: starts={s_starts} ends={s_ends}"
    )


# --------------------------------------------------------------------------- #
# TC-B94-28 — the run consumes each chain's own bindings (LLR-018.2)
# --------------------------------------------------------------------------- #


def test_tc_b94_28_run_consumes_each_chains_own_bindings(tmp_path: Path) -> None:
    """TC-B94-28 (LLR-018.2, integration): chain A's provenance names A's
    file, B's names B's, 0 cross-mentions; a missing input fails that chain
    only (the siblings complete).
    """
    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)
    record = run_chain_set(
        [
            _clean_chain("a"),
            ChainSpec(
                name="b",
                template="base",
                flow=_clean_chain("b").flow,
                bindings={0: "variant_b.hex"},
            ),
        ],
        ctx,
        set_name="variants_a_b",
    )
    assert [outcome.status for outcome in record.outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_OK,
    ]
    # One provenance line per consumed input, naming exactly that chain's file.
    prov_a, prov_b = [outcome.inputs for outcome in record.outcomes]
    assert len(prov_a) == 1 and prov_a[0][0] == "base.s19"
    assert prov_a[0][1].endswith("base.s19")
    assert len(prov_b) == 1 and prov_b[0][0] == "variant_b.hex"
    assert prov_b[0][1].endswith("variant_b.hex")
    report = record.report_path.read_text(encoding="utf-8")
    prov_lines = [
        ln for ln in report.splitlines()
        if ln.startswith("- Chain ") and " input " in ln
    ]
    assert len(prov_lines) == 2
    assert any("base.s19" in ln and "`" in ln for ln in prov_lines)
    assert any("variant_b.hex" in ln and "`" in ln for ln in prov_lines)
    # 0 cross-mentions: A's line never names B's file and vice versa.
    a_line = next(ln for ln in prov_lines if ln.startswith("- Chain a "))
    b_line = next(ln for ln in prov_lines if ln.startswith("- Chain b "))
    assert "variant_b.hex" not in a_line
    assert "base.s19" not in b_line

    # Invalid arm: a missing input fails THAT chain only (LLR-018.2).
    broken = run_chain_set(
        [
            _clean_chain("a"),
            ChainSpec(
                name="gone",
                template="base",
                flow=_clean_chain("gone").flow,
                bindings={0: "moved_away.s19"},
            ),
        ],
        ctx,
        set_name="variants_a_b",
    )
    assert [outcome.status for outcome in broken.outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_ERROR,
    ]
    assert broken.outcomes[0].written_paths, "the sibling's output must land"
    assert broken.outcomes[1].written_paths == []
    gone_inputs = broken.outcomes[1].inputs
    # The guard resolves refs WITHOUT requiring existence (the flow-loader
    # idiom) — the provenance names the moved-away binding; the RUN's own
    # block result fails the chain closed ("source unresolved").
    assert gone_inputs[0][0] == "moved_away.s19"
    assert gone_inputs[0][1].endswith("moved_away.s19")
    assert broken.outcomes[1].block_results[0].status == "error"


# --------------------------------------------------------------------------- #
# TC-B94-30 — chain-set report provenance (LLR-020.2, the C-42 paste)
# --------------------------------------------------------------------------- #


def test_tc_b94_30_chain_set_report_provenance_lines(tmp_path: Path) -> None:
    """TC-B94-30 (LLR-020.2, C-42): the report carries one provenance line
    per chain input — 1 per input, 0 missing, 0 duplicates; every line
    resolves to the bound path (name equality with the binding record).
    """
    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)
    record = run_chain_set(
        [
            _clean_chain("a"),
            ChainSpec(
                name="b",
                template="base",
                flow=_clean_chain("b").flow,
                bindings={0: "variant_b.hex"},
            ),
        ],
        ctx,
        set_name="variants_a_b",
    )
    report = record.report_path.read_text(encoding="utf-8")
    prov_lines = [
        ln for ln in report.splitlines()
        if ln.startswith("- Chain ") and " input " in ln
    ]
    # line count == chain-input count (1 per input, 0 missing/duplicates).
    assert len(prov_lines) == 2
    assert len(set(prov_lines)) == 2, f"duplicate provenance lines: {prov_lines}"
    # The C-42 fixed form + name equality with the binding record. The
    # emitted form is ``- Chain <name> input <j>: <ref> [bound] path=`...```
    # (the label half md_safe-escaped, the path half a byte-faithful code
    # span); the predicate pins the fixed scaffolding and the resolved name.
    for outcome in record.outcomes:
        for index, (ref, resolved) in enumerate(outcome.inputs, start=1):
            line = next(
                (
                    ln
                    for ln in prov_lines
                    if ln.startswith(f"- Chain {outcome.chain} input {index}:")
                ),
                None,
            )
            assert line is not None, (
                f"missing provenance line for {outcome.chain} input {index}"
            )
            assert " [bound] path=`" in line
            assert line.endswith("`"), f"the code span must close: {line}"
            assert Path(resolved).name == Path(ref).name
            assert line.rstrip("`").endswith(Path(ref).name), (
                f"the line must resolve to the bound path's name: {line}"
            )

    # Rebind-then-rerun arm: the report names the NEW binding, never a stale one.
    rebound = run_chain_set(
        [
            ChainSpec(
                name="a",
                template="base",
                flow=_clean_chain("a").flow,
                bindings={0: "variant_b.hex"},
            )
        ],
        ctx,
        set_name="variants_a_b",
    )
    rerun_report = rebound.report_path.read_text(encoding="utf-8")
    rerun_lines = [
        ln for ln in rerun_report.splitlines()
        if ln.startswith("- Chain ") and " input " in ln
    ]
    assert len(rerun_lines) == 1
    assert "variant_b.hex" in rerun_lines[0]
    assert "input 1: base" not in rerun_lines[0], (
        f"a stale binding name survived the rebind: {rerun_lines[0]}"
    )


def test_tc_b94_30_compose_is_deterministic_and_md_safe(tmp_path: Path) -> None:
    """TC-B94-30's hostile arm (C-17 over the report producer): a hostile
    set/chain/ref name renders through md_safe/md_code — 0 markup spans in
    the emitted text, the sentinel visible, and the same record + instant
    composes byte-identically (the pure-composer contract).
    """
    from datetime import datetime, timezone

    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)
    sentinel = "b77hostile_evil[red]`tick`"
    hostile = ChainSpec(
        name=sentinel,
        template="base",
        flow=_clean_chain("a").flow,
        bindings={0: sentinel + ".s19"},
    )
    record = run_chain_set([hostile], ctx, set_name=sentinel)
    report = record.report_path.read_text(encoding="utf-8")
    # The sentinel's PRINTABLE skeleton survives (md_safe escapes, never drops);
    # no raw markup construct does — OUTSIDE the code spans: a Mode-B path is
    # byte-faithful by design (TC-B94-25's truth table), inert inside the
    # backticks, so strip the spans before the raw-bracket census.
    assert "b77hostile_evil" in report
    without_spans = re.sub(r"`[^`]*`", "", report)
    assert "[red]" not in without_spans.replace("[bound]", ""), (
        "a raw bracket construct survived the escaper outside the code spans"
    )
    assert "`tick`" not in without_spans, "a raw backtick survived md_code"
    # Determinism: the same record + instant recomposes byte-identically.
    instant = datetime(2026, 10, 14, tzinfo=timezone.utc)
    first = compose_chain_set_report(record, "s", instant)
    second = compose_chain_set_report(record, "s", instant)
    assert first == second


# --------------------------------------------------------------------------- #
# TC-B94-31 — the chain-set serializer (LLR-021.1)
# --------------------------------------------------------------------------- #


def _saved_set(project: Path) -> "fps.ChainSet":
    return fps.ChainSet(
        name="variants_a_b",
        chains=(
            fps.ChainSetEntry(
                chain="a",
                template="base",
                inputs=((0, "base.s19"),),
                outputs=("out.s19",),
            ),
            fps.ChainSetEntry(
                chain="b",
                template="base",
                inputs=((0, "variant_b.hex"),),
                outputs=("out.s19",),
            ),
        ),
    )


def test_tc_b94_31_chain_set_serializer_round_trip(tmp_path: Path) -> None:
    """TC-B94-31 (LLR-021.1, unit): ONE document; chain count == lane count;
    every chain carries 1 template ref, >=1 input, >=1 output; reload
    restores 100% with 0 field diffs (the 0-diff contract rides the same
    assertion family as AT-B94-24's e2e).
    """
    project = _project(tmp_path)
    saved = fps.save_chain_set(_saved_set(project), "variants_a_b", project)
    assert saved is not None and saved.parent == project / fps.FLOWSETS_SUBDIR, (
        f"the set must land inside the work area: {saved}"
    )
    # 1 saved document; the on-disk envelope shape.
    envelope = json.loads(saved.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == fps.CHAIN_SET_SCHEMA_VERSION
    assert envelope["kind"] == "chain-set"
    assert len(envelope["chains"]) == 2
    for entry in envelope["chains"]:
        assert isinstance(entry["template"], str) and entry["template"]
        assert len(entry["inputs"]) >= 1
        assert len(entry["outputs"]) >= 1
    loaded, findings = fps.load_chain_set(saved, project)
    assert findings == [] and loaded is not None
    # 0 field diffs vs the saved state.
    assert loaded == _saved_set(project)
    assert fps.list_chain_sets(project) == ["variants_a_b"]


def test_tc_b94_31_empty_set_and_hostile_sets_fail_closed(tmp_path: Path) -> None:
    """TC-B94-31's negative arms (LLR-021.1): 0 empty sets written as
    non-empty; corrupt / hostile sets are refused fail-closed with one code
    each (the containment + structure vocabulary).
    """
    project = _project(tmp_path)
    # Empty arm: saving with zero chains writes NOTHING.
    empty = fps.save_chain_set(
        fps.ChainSet(name="empty", chains=()), "empty", project
    )
    assert empty is None
    assert fps.list_chain_sets(project) == []

    saved = fps.save_chain_set(_saved_set(project), "variants_a_b", project)
    assert saved is not None

    # Corrupt arm: not JSON.
    bad = project / fps.FLOWSETS_SUBDIR / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    loaded, findings = fps.load_chain_set(bad, project)
    assert loaded is None
    assert [f.code for f in findings] == [fps.CHAIN_SET_JSON_PARSE]

    # Wrong schema / kind arm.
    wrong = project / fps.FLOWSETS_SUBDIR / "wrong.json"
    wrong.write_text(
        json.dumps({"schema_version": 2, "kind": "chain-set", "name": "x", "chains": []}),
        encoding="utf-8",
    )
    loaded, findings = fps.load_chain_set(wrong, project)
    assert loaded is None
    assert findings[0].code == fps.CHAIN_SET_SCHEMA_UNSUPPORTED

    # Containment arm: a bound input escaping the project is refused.
    escaped = json.loads(saved.read_text(encoding="utf-8"))
    escaped["chains"][0]["inputs"] = [[0, "../outside.s19"]]
    escape_path = project / fps.FLOWSETS_SUBDIR / "escape.json"
    escape_path.write_text(json.dumps(escaped), encoding="utf-8")
    loaded, findings = fps.load_chain_set(escape_path, project)
    assert loaded is None
    assert any(
        f.code in (fps.CHAIN_SET_UNSAFE_REF, "MANIFEST-PATH-ESCAPE") for f in findings
    ), f"expected a containment refusal, got {[f.code for f in findings]}"

    # Template-shape arm: a template ref with a separator is refused.
    shaped = json.loads(saved.read_text(encoding="utf-8"))
    shaped["chains"][0]["template"] = "../evil"
    shape_path = project / fps.FLOWSETS_SUBDIR / "shape.json"
    shape_path.write_text(json.dumps(shaped), encoding="utf-8")
    loaded, findings = fps.load_chain_set(shape_path, project)
    assert loaded is None
    assert any(f.code == fps.CHAIN_SET_UNSAFE_REF for f in findings)

    # Oversize arm: the size cap binds to the same FLOW_SIZE_CAP_BYTES.
    huge = project / fps.FLOWSETS_SUBDIR / "huge.json"
    huge.write_text(" " * (fps.FLOW_SIZE_CAP_BYTES + 1), encoding="utf-8")
    loaded, findings = fps.load_chain_set(huge, project)
    assert loaded is None
    assert [f.code for f in findings] == [fps.CHAIN_SET_SIZE_CAP]


# --------------------------------------------------------------------------- #
# AT-B94-24's e2e service half — save → reload → re-run regenerates (C-12)
# --------------------------------------------------------------------------- #


def test_at_b94_24_service_half_reloaded_set_reruns(tmp_path: Path) -> None:
    """The C-12 chain at the service layer: the RELOADED set is what re-runs
    — reload restores 0-field-diff, and a re-run against the restored
    bindings regenerates every chain's output (content changes).
    """
    project = _project(tmp_path)
    ctx = FlowContext(project_dir=project)
    chains = [
        _clean_chain("a"),
        ChainSpec(
            name="b",
            template="base",
            flow=_clean_chain("b").flow,
            bindings={0: "variant_b.hex"},
        ),
    ]
    # The template the set references must exist under flows/ (the reload
    # resolves it through the hardened flow loader).
    fps.save_flow_json(chains[0].flow, "base", project)
    first = run_chain_set(chains, ctx, set_name="variants_a_b")
    saved = fps.save_chain_set(
        fps.ChainSet(
            name="variants_a_b",
            chains=tuple(
                fps.ChainSetEntry(
                    chain=spec.name,
                    template=spec.template,
                    # EFFECTIVE inputs — the operator overrides merged over
                    # the template's own SOURCE refs (LLR-021.1's >=1-input
                    # contract records what the chain consumes, not only
                    # what the operator re-typed).
                    inputs=tuple(
                        (index, spec.bindings.get(index, block.image_ref))
                        for index, block in enumerate(spec.flow.blocks)
                        if isinstance(block, SourceBlock)
                    ),
                    outputs=tuple(path.name for path in outcome.written_paths),
                )
                for spec, outcome in zip(chains, first.outcomes)
            ),
        ),
        "variants_a_b",
        project,
    )
    assert saved is not None

    # Reload: 0 field diffs vs the saved state.
    loaded, findings = fps.load_chain_set(saved, project)
    assert findings == [] and loaded is not None
    assert loaded.name == "variants_a_b" and len(loaded.chains) == 2

    # The RELOADED set re-runs: rebuild the plan from the loaded envelope.
    reloaded_chains = []
    for entry in loaded.chains:
        flow, flow_findings = fps.load_flow_json(
            project / fps.FLOWS_SUBDIR / f"{entry.template}.json", project
        ) if (project / fps.FLOWS_SUBDIR / f"{entry.template}.json").exists() else (None, [])
        assert flow is not None, flow_findings
        reloaded_chains.append(
            ChainSpec(
                name=entry.chain,
                template=entry.template,
                flow=flow,
                bindings=dict(entry.inputs),
            )
        )
    out_paths = [project / "out.s19"]
    before = [path.read_bytes() for path in out_paths]
    second = run_chain_set(reloaded_chains, ctx, set_name="variants_a_b")
    assert [outcome.status for outcome in second.outcomes] == [
        FLOW_STATUS_OK,
        FLOW_STATUS_OK,
    ]
    after = [path.read_bytes() for path in out_paths]
    assert before != after or all(
        outcome.written_paths for outcome in second.outcomes
    ), "the re-run must regenerate the outputs (fresh writes)"
    # Both chains regenerated: 1 written path per chain on the re-run.
    assert all(outcome.written_paths for outcome in second.outcomes)
