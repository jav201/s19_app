"""Flow Builder run-engine tests — batch-51 Inc-1 keel (R-TUI-085/086/087).

Black-box ATs drive the shipped ``run_flow`` engine surface directly (the
Direction-A panel is Inc-2); white-box TCs pin the LLR mechanisms. Projects
are built under a real ``.s19tool/workarea/`` root because WRITE-OUT stages
through the work area (``save_patched_image`` containment) — the same setup
``test_flow_execution`` uses.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.tui.services import flow_execution_service
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    WRITE_FMT_S19,
    CheckBlock,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_s19

#: Minimal CLEAN S19 — 4 bytes (01 02 03 04) at 0x1000 (checksum-verified).
_S19_CLEAN = "S107100001020304DE\nS9030000FC\n"

#: Integrity-flagged S19 — a valid data record at 0x1000 plus a single
#: bad-checksum data record at 0x2000 (collected as ONE validation error by the
#: collect-don't-abort parser; the image still loads with both records mapped).
_S19_ONE_ERROR = (
    "S107100001020304DE\n"
    "S107200005060708FF\n"  # checksum should be BE -> one validation error
    "S9030000FC\n"
)


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _check_doc(entries: list[dict]) -> str:
    """A v2 ``s19app-changeset`` check document JSON string."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _reload_s19(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


# ===========================================================================
# US-085 / R-TUI-085 — LOAD integrity notices (notify, don't block)
# ===========================================================================


def test_at085a_load_notices_downstream_runs(tmp_path: Path) -> None:
    """AT-085a (black-box, US-085): a flow whose SOURCE targets an
    integrity-flagged image reports the SOURCE block ``notices`` with a WARN
    finding, and the downstream WRITE-OUT still runs and still produces a file.

    Boundary (qa m3): exactly one parser error -> exactly one finding.
    RED before the engine edit: the SOURCE-ok path emits ``ok`` with no
    findings, so ``status == "notices"`` and ``len(findings) == 1`` both fail.
    """
    project = _make_project(tmp_path, {"prg.s19": _S19_ONE_ERROR})
    flow = Flow(
        name="load-notices",
        blocks=[
            SourceBlock("prg.s19", file_type=WRITE_FMT_S19),
            WriteOutBlock("out.s19", fmt=WRITE_FMT_S19),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    source = result.block_results[0]
    assert source.status == BLOCK_STATUS_NOTICES
    assert len(source.findings) == 1  # exactly-one-error boundary
    # C-9: the finding message names the numeric line + diagnostic, and NEVER
    # echoes the raw record content (the "05060708" data payload of the flagged
    # S107200005060708FF line must not appear).
    message = source.findings[0].message
    assert re.match(r"^line \d+: ", message), message
    assert "05060708" not in message, message
    # downstream still ran and produced its file (chain not blocked).
    assert result.block_results[1].status == BLOCK_STATUS_OK
    assert len(result.written_paths) == 1
    assert result.written_paths[0].exists()


def test_at085b_unresolvable_source_stops_and_skips(tmp_path: Path) -> None:
    """AT-085b (black-box, US-085): an unresolvable SOURCE image is a STOP —
    the SOURCE block errors, every downstream block is ``skipped``, and no file
    is written (the abort-asymmetry vs a CHECK failure).
    """
    project = _make_project(tmp_path, {})
    flow = Flow(
        name="load-stop",
        blocks=[
            SourceBlock("missing.s19"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[0].status == BLOCK_STATUS_ERROR
    assert result.block_results[1].status == BLOCK_STATUS_SKIPPED
    assert result.written_paths == []


def test_tc085_2_zero_error_image_stays_ok(tmp_path: Path) -> None:
    """TC-085.2 boundary (LLR-085.2): a zero-error image keeps ``ok`` with no
    findings — the notices path fires only when ``loaded.errors`` is non-empty.
    """
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    flow = Flow(name="clean", blocks=[SourceBlock("prg.s19")])

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[0].status == BLOCK_STATUS_OK
    assert result.block_results[0].findings == []


def test_tc085_3_findings_count_matches_load_errors(tmp_path: Path) -> None:
    """TC-085.3 (LLR-085.2): one WARN finding is appended per parser error and
    the working image is still threaded downstream (image intact)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_ONE_ERROR})
    loaded_errors = build_loaded_s19(
        project / "prg.s19", S19File(str(project / "prg.s19")), None, None
    ).errors
    flow = Flow(
        name="count",
        blocks=[SourceBlock("prg.s19"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    source = result.block_results[0]
    assert len(source.findings) == len(loaded_errors) >= 1
    assert result.block_results[1].status == BLOCK_STATUS_OK  # image threaded


# ===========================================================================
# US-086 / R-TUI-086 — CHECK block (read-only, chain-never-blocked, gating)
# ===========================================================================


def test_at086a_check_passthrough_bytes_identical(tmp_path: Path) -> None:
    """AT-086a (black-box, US-086): LOAD->CHECK->WRITE-OUT produces a file whose
    bytes are byte-identical to LOAD->WRITE-OUT (the CHECK passes the image
    through unchanged), and the CHECK report is present.

    qa m1: the check address (0x9000) is derived from OUTSIDE the seeded ranges
    (0x1000..0x1003), so the entry is uncheckable, never a false pass/fail.
    """
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "checks.json": _check_doc(
                [{"type": "bytes", "address": "0x9000", "bytes": "AA"}]
            ),
        },
    )

    with_check = run_flow(
        Flow(
            "with-check",
            blocks=[
                SourceBlock("prg.s19"),
                CheckBlock("checks.json"),
                WriteOutBlock("out_a.s19"),
            ],
        ),
        FlowContext(project_dir=project),
    )
    without_check = run_flow(
        Flow(
            "no-check",
            blocks=[SourceBlock("prg.s19"), WriteOutBlock("out_b.s19")],
        ),
        FlowContext(project_dir=project),
    )

    # pass-through: identical written bytes with and without the CHECK block.
    assert _read_bytes(with_check.written_paths[0]) == _read_bytes(
        without_check.written_paths[0]
    )
    # CHECK report present (aggregate counts surfaced on the block summary).
    check_block = with_check.block_results[1]
    assert check_block.kind == "check"
    assert "passed=" in check_block.summary
    assert "failed=" in check_block.summary
    assert "uncheckable=" in check_block.summary


def test_at086b_unreadable_check_doc_block_own_op_downstream_runs(
    tmp_path: Path,
) -> None:
    """AT-086b (black-box, US-086): under ``block-own-op`` an unreadable
    check-doc marks the CHECK block ``error`` while the downstream WRITE-OUT
    STILL produces its file — the chain is never blocked (abort-asymmetry).
    """
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    flow = Flow(
        "own-op-error",
        blocks=[
            SourceBlock("prg.s19"),
            CheckBlock("missing.json", gating=CHECK_GATING_BLOCK_OWN),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_ERROR
    assert result.block_results[2].status == BLOCK_STATUS_OK
    assert len(result.written_paths) == 1  # downstream still produced its file


def test_at086c_gating_flag_drives_observable_status_change(
    tmp_path: Path,
) -> None:
    """AT-086c (black-box, US-086 — the hidden-chain-kill guard): the SAME
    unreadable check-doc under ``advisory`` vs ``block-own-op`` yields a
    DIFFERENT CHECK block status (``notices`` vs ``error``), proving that
    driving the flag caused the change; in BOTH runs the downstream WRITE-OUT
    still produces its file (chain never blocked).

    Counterfactual: an impl that ignores the gating flag shows the SAME status
    both times -> this test goes RED.
    """
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})

    def _run(gating: str):
        return run_flow(
            Flow(
                f"gated-{gating}",
                blocks=[
                    SourceBlock("prg.s19"),
                    CheckBlock("missing.json", gating=gating),
                    WriteOutBlock(f"out_{gating}.s19"),
                ],
            ),
            FlowContext(project_dir=project),
        )

    advisory = _run(CHECK_GATING_ADVISORY)
    block_own = _run(CHECK_GATING_BLOCK_OWN)

    # (a) the flag drives an observable status difference on the SAME input.
    assert advisory.block_results[1].status == BLOCK_STATUS_NOTICES
    assert block_own.block_results[1].status == BLOCK_STATUS_ERROR
    assert (
        advisory.block_results[1].status != block_own.block_results[1].status
    )
    # (b) the chain is never blocked either way — WRITE-OUT produces in both.
    assert len(advisory.written_paths) == 1
    assert len(block_own.written_paths) == 1


def test_tc086_2_check_reports_counts_image_intact(tmp_path: Path) -> None:
    """TC-086.2 (LLR-086.2): the CHECK block stores the three aggregate counts
    on its summary and leaves the image intact (the downstream WRITE-OUT
    reproduces the loaded bytes)."""
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "checks.json": _check_doc(
                [{"type": "bytes", "address": "0x1000", "bytes": "01"}]  # inside -> pass
            ),
        },
    )
    flow = Flow(
        "counts",
        blocks=[
            SourceBlock("prg.s19"),
            CheckBlock("checks.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    summary = result.block_results[1].summary
    assert "passed=1" in summary
    assert "failed=0" in summary
    assert "uncheckable=0" in summary
    # image intact -> WRITE-OUT reproduces the loaded bytes.
    assert _reload_s19(result.written_paths[0])[0x1000] == 0x01


def test_tc086_4_chain_never_blocked_matrix(tmp_path: Path) -> None:
    """TC-086.4 (LLR-086.4): across {advisory|block-own-op} x {failing entries|
    unreadable doc}, a downstream WRITE-OUT ALWAYS runs and the flow is never
    FAILED; only the block-own-op x unreadable cell flips the CHECK to ``error``.
    """
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            # inside address with a WRONG expected byte -> one failing entry.
            "fail.json": _check_doc(
                [{"type": "bytes", "address": "0x1000", "bytes": "FF"}]
            ),
        },
    )

    cases = [
        (CHECK_GATING_ADVISORY, "fail.json", BLOCK_STATUS_NOTICES),
        (CHECK_GATING_BLOCK_OWN, "fail.json", BLOCK_STATUS_NOTICES),
        (CHECK_GATING_ADVISORY, "missing.json", BLOCK_STATUS_NOTICES),
        (CHECK_GATING_BLOCK_OWN, "missing.json", BLOCK_STATUS_ERROR),
    ]
    for idx, (gating, ref, expected) in enumerate(cases):
        flow = Flow(
            f"matrix-{idx}",
            blocks=[
                SourceBlock("prg.s19"),
                CheckBlock(ref, gating=gating),
                WriteOutBlock(f"m_{idx}.s19"),
            ],
        )
        result = run_flow(flow, FlowContext(project_dir=project))
        assert result.block_results[1].status == expected, (gating, ref)
        assert len(result.written_paths) == 1, (gating, ref)  # chain never blocked
        assert result.status != FLOW_STATUS_ERROR, (gating, ref)


def test_tc086_5_unreadable_check_doc_non_aborting(tmp_path: Path) -> None:
    """TC-086.5 (LLR-086.5): an unreadable check-doc leaves the chain intact in
    both gating modes; the WRITE-OUT file is produced regardless."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    for gating in (CHECK_GATING_ADVISORY, CHECK_GATING_BLOCK_OWN):
        flow = Flow(
            f"unreadable-{gating}",
            blocks=[
                SourceBlock("prg.s19"),
                CheckBlock("missing.json", gating=gating),
                WriteOutBlock(f"u_{gating}.s19"),
            ],
        )
        result = run_flow(flow, FlowContext(project_dir=project))
        assert result.block_results[2].status == BLOCK_STATUS_OK
        assert len(result.written_paths) == 1


def test_tc086_6_check_body_exception_never_aborts_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-086.6 (LLR-086.4 STRUCTURAL): if ANY step of the CHECK branch body
    raises — here a malformed ``CheckRunResult`` whose ``.aggregates`` misses a
    key, past the read/run calls — the chain is STILL never blocked: the CHECK
    block is not ``skipped``, the flow is not FAILED, and the downstream
    WRITE-OUT still produces its file.

    Counterfactual: with the pre-fix narrow try (guarding only read+run), the
    aggregate-extraction ``KeyError`` reaches the outer per-block handler ->
    ``aborted=True`` -> downstream skipped -> RED. The widened try makes the
    invariant structural, not contract-conditional.
    """

    class _BadResult:
        aggregates = {"failed": 0}  # missing "passed"/"uncheckable" -> KeyError

    monkeypatch.setattr(
        flow_execution_service, "run_check_document",
        lambda *a, **k: _BadResult(),
    )
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_CLEAN,
            "checks.json": _check_doc(
                [{"type": "bytes", "address": "0x1000", "bytes": "01"}]
            ),
        },
    )
    flow = Flow(
        "bad-agg",
        blocks=[
            SourceBlock("prg.s19"),
            CheckBlock("checks.json"),  # advisory default
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status != BLOCK_STATUS_SKIPPED
    assert result.block_results[2].status == BLOCK_STATUS_OK  # downstream ran
    assert len(result.written_paths) == 1  # file produced -> chain not blocked
    assert result.status != FLOW_STATUS_ERROR  # aborted stayed False


# ===========================================================================
# US-087 / R-TUI-087 — status model + completed-with-issues (amber)
# ===========================================================================


def test_at087a_issues_distinct_from_failed(tmp_path: Path) -> None:
    """AT-087a (black-box, US-087): a run that produces output WITH advisories
    is ``completed-with-issues`` (amber), distinct from a broken-image run that
    is ``error`` (FAILED).
    """
    project = _make_project(
        tmp_path, {"good.s19": _S19_ONE_ERROR}
    )
    issues = run_flow(
        Flow("issues", blocks=[SourceBlock("good.s19"), WriteOutBlock("out.s19")]),
        FlowContext(project_dir=project),
    )
    failed = run_flow(
        Flow("failed", blocks=[SourceBlock("missing.s19"), WriteOutBlock("x.s19")]),
        FlowContext(project_dir=project),
    )

    assert issues.status == FLOW_STATUS_ISSUES
    assert len(issues.written_paths) == 1  # output WAS produced
    assert failed.status == FLOW_STATUS_ERROR
    assert failed.written_paths == []  # no output
    assert issues.status != failed.status


def test_at087b_clean_run_is_ok(tmp_path: Path) -> None:
    """AT-087b (black-box, US-087 boundary): a fully clean run is ``ok``
    (CLEAN) — no notices, no findings, no non-aborting error."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    result = run_flow(
        Flow("clean", blocks=[SourceBlock("prg.s19"), WriteOutBlock("out.s19")]),
        FlowContext(project_dir=project),
    )
    assert result.status == FLOW_STATUS_OK


def test_tc087_2_three_way_rollup(tmp_path: Path) -> None:
    """TC-087.2 (LLR-087.2): the three fixtures map to ok / completed-with-issues
    / error, and a non-aborting CHECK ``error`` yields ISSUES (NOT error).
    """
    project = _make_project(
        tmp_path,
        {"clean.s19": _S19_CLEAN, "dirty.s19": _S19_ONE_ERROR},
    )
    # (a) CLEAN
    clean = run_flow(
        Flow("a", blocks=[SourceBlock("clean.s19"), WriteOutBlock("a.s19")]),
        FlowContext(project_dir=project),
    )
    assert clean.status == FLOW_STATUS_OK
    # (b) ISSUES via a non-aborting CHECK own-op error (block-own-op, missing doc)
    check_issue = run_flow(
        Flow(
            "b",
            blocks=[
                SourceBlock("clean.s19"),
                CheckBlock("missing.json", gating=CHECK_GATING_BLOCK_OWN),
                WriteOutBlock("b.s19"),
            ],
        ),
        FlowContext(project_dir=project),
    )
    assert check_issue.block_results[1].status == BLOCK_STATUS_ERROR
    assert check_issue.status == FLOW_STATUS_ISSUES  # NOT error — image intact
    # (c) FAILED via an aborting SOURCE error
    failed = run_flow(
        Flow("c", blocks=[SourceBlock("missing.s19"), WriteOutBlock("c.s19")]),
        FlowContext(project_dir=project),
    )
    assert failed.status == FLOW_STATUS_ERROR


# ===========================================================================
# §6.5 AMD-1 / LLR-088.4 — image_ranges footprint carrier (Inc-2 ribbon data)
# ===========================================================================


def test_tc088_image_ranges_carries_final_footprint(tmp_path: Path) -> None:
    """TC-088 (§6.5 AMD-1, additive per §6.3 R-6): ``run_flow`` carries the
    working image's FINAL ``(start, end)`` footprint on
    ``FlowRunResult.image_ranges`` (the Direction-A ribbon's data source); an
    unresolvable SOURCE leaves it empty.

    RED before the engine edit: ``FlowRunResult`` had no ``image_ranges`` field,
    so the attribute access / equality both fail.
    """
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})
    source_ranges = [
        (int(s), int(e))
        for s, e in build_loaded_s19(
            project / "prg.s19", S19File(str(project / "prg.s19")), None, None
        ).ranges
    ]

    loaded = run_flow(
        Flow("f", blocks=[SourceBlock("prg.s19"), WriteOutBlock("out.s19")]),
        FlowContext(project_dir=project),
    )
    # a CHECK is read-only and PATCH mutates in place, so the carried footprint
    # equals the SOURCE footprint — and is non-empty.
    assert loaded.image_ranges == source_ranges
    assert loaded.image_ranges  # non-empty

    # unresolvable SOURCE -> no image was ever loaded -> empty footprint.
    aborted = run_flow(
        Flow("g", blocks=[SourceBlock("missing.s19"), WriteOutBlock("x.s19")]),
        FlowContext(project_dir=project),
    )
    assert aborted.status == FLOW_STATUS_ERROR
    assert aborted.image_ranges == []
