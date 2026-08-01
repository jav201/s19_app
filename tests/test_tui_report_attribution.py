"""batch-76 Inc-3 — ``HLR-110``: an internal failure is not blamed on the operator.

THE DEFECT. ``generate_project_report`` sat INSIDE a ``try`` whose
``except ValueError`` surfaces ``"Report rejected: ..."`` — the operator-input
rejection path. So any ``ValueError`` escaping the generator, for any internal
reason, told the operator that THEY had typed something invalid. The
operator-input span is the options construction and the scope guard; those are
the only places a ``ValueError`` legitimately means "your input was out of
domain" (P-11).

⚠ **WHY THIS INCREMENT COMES AFTER Inc-2, AND WHY THAT IS LOAD-BEARING.** Before
Inc-2 there was a natural ``Length``-driven ``ValueError`` to trigger this with.
``_format_length`` removed it. So this suite must **INJECT** its fault — and
that is the better test: it makes ``AT-260`` a **general** attribution property
("a ValueError from the generator is the tool's fault") rather than one welded
to the D2 bug that happened to expose it. Inverting the increment order would
have produced a weaker acceptance that passed for an accidental reason.

The injected exception is deliberately a ``ValueError`` — **the same type the
rejection branch legitimately catches**. A ``RuntimeError`` fixture already
takes the tool-failure arm on the BASE tree and would prove nothing.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
from typing import List, Tuple

import pytest

from s19_app.tui import app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.model import ChangeSummary, ChangeSummaryEntry
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.report_service import (
    REPORT_SOURCE_DEFAULT,
    REPORTS_DIR_NAME,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult


# ---------------------------------------------------------------------------
# Scaffold — drives the SHIPPED worker, not a re-implementation of it.
# ---------------------------------------------------------------------------


def _result(vid: str = "v0") -> VariantExecutionResult:
    entry = ChangeSummaryEntry(
        entry_type="bytes",
        address_start=0x8000_0000,
        address_end=0x8000_0004,
        before_bytes=(0x10, 0x11, 0x12, 0x13),
        after_bytes=(0xA0, 0xA1, 0xA2, 0xA3),
        disposition="applied",
        linkage="standalone",
        linkage_symbol=None,
    )
    summary = ChangeSummary(
        source_path=Path("chg.json"),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=vid,
        counts={"applied": 1},
        entries=[entry],
        issues=[],
    )
    return VariantExecutionResult(
        variant_id=vid, status="ok", change_summaries=[summary], check_results=[]
    )


def _variant_set() -> ProjectVariantSet:
    return ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(variant_id="v0", path=Path("v0.s19"), file_type="s19"),
        ),
        active_id="v0",
    )


async def _drive_worker(
    tmp_path: Path, context_bytes: int = 64
) -> Tuple[List[str], List[int], Path]:
    """Run the SHIPPED report worker to completion and capture what it surfaced.

    ``last`` is supplied so the worker takes its retained-snapshot path and
    skips ``execute_project_variants`` entirely — the heavy fresh run is not
    what this file is about, and skipping it keeps the node fast without
    bypassing the code under test.
    """
    project_dir = tmp_path / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)

    statuses: List[str] = []
    progress: List[int] = []
    app = S19TuiApp()

    async with app.run_test() as pilot:
        app.set_status = lambda message: statuses.append(str(message))  # type: ignore[assignment]
        app.set_progress = lambda value: progress.append(int(value))  # type: ignore[assignment]

        last = (project_dir, "active", REPORT_SOURCE_DEFAULT, [_result()])
        app._start_generate_report_worker(
            project_dir, _variant_set(), context_bytes, last, [], (), None
        )
        await app.workers.wait_for_complete()
        await pilot.pause()

    return statuses, progress, project_dir


def _reports(project_dir: Path) -> List[Path]:
    reports_dir = project_dir / REPORTS_DIR_NAME
    return sorted(reports_dir.glob("*.md")) if reports_dir.exists() else []


# ---------------------------------------------------------------------------
# AT-260 / AT-261 — the two attribution arms. These are the DISCRIMINATING nodes.
# ---------------------------------------------------------------------------


def test_at260_a_valueerror_from_the_generator_is_the_tools_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-260 — an injected ``ValueError`` yields ``Report failed:``, not ``rejected``.

    Mutation: move ``generate_project_report`` back inside the ``try`` guarded by
    ``except ValueError`` (i.e. delete the second ``try`` and the LLR-110.1
    split).
    """

    def boom(*_args, **_kwargs):
        raise ValueError("internal accounting slip, not operator input")

    monkeypatch.setattr(app_module, "generate_project_report", boom)
    statuses, _progress, project_dir = asyncio.run(_drive_worker(tmp_path))

    assert statuses, "the worker surfaced no status at all"
    final = statuses[-1]
    assert final.startswith("Report failed:"), (
        f"an internal ValueError was attributed to the operator: {final!r}"
    )
    assert not any(s.startswith("Report rejected:") for s in statuses), (
        "the rejection path was taken for a tool-internal failure"
    )


def test_at261_out_of_domain_operator_input_is_still_a_rejection(
    tmp_path: Path,
) -> None:
    """AT-261 — an out-of-domain ``ReportOptions`` field STILL says ``rejected``.

    The other half of the property, and the one a careless fix breaks: it is not
    enough to stop blaming the operator for the tool's faults; the operator must
    still be told when the input really was theirs.

    Mutation: ``except ValueError`` -> ``except Exception: pass``.
    """
    statuses, _progress, project_dir = asyncio.run(
        _drive_worker(tmp_path, context_bytes=-1)
    )

    assert statuses, "the worker surfaced no status at all"
    final = statuses[-1]
    assert final.startswith("Report rejected:"), (
        f"out-of-domain operator input was not reported as a rejection: {final!r}"
    )
    assert "context_bytes" in final, (
        "the rejection does not name the field the operator got wrong"
    )
    assert _reports(project_dir) == []


def test_at262_pin_neither_path_leaves_a_report_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-262 (PIN) — fail closed: no file in ``reports/`` on EITHER branch.

    ⚠ Labelled a PIN: it holds by construction (P-12 — the generator writes
    ONCE, at the end, via a single ``target.write_bytes``), so it cannot
    discriminate this change. It owns its own node rather than riding along
    inside AT-260, because an AT satisfied only in combination with another is
    UNREALIZED (C-18).
    """

    def boom(*_args, **_kwargs):
        raise ValueError("injected")

    monkeypatch.setattr(app_module, "generate_project_report", boom)
    _s, _p, failed_dir = asyncio.run(_drive_worker(tmp_path / "fail"))
    assert _reports(failed_dir) == [], "the tool-failure path left a report behind"

    _s2, _p2, rejected_dir = asyncio.run(
        _drive_worker(tmp_path / "reject", context_bytes=-1)
    )
    assert _reports(rejected_dir) == [], "the rejection path left a report behind"


def test_tc571_the_failure_path_logs_a_failure_not_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-571 — the LOG agrees with the status; the record must not contradict it.

    The status line is what the operator reads now; the log is what an auditor
    reads later. Fixing one and leaving the other saying "rejected" would keep
    the defect in the durable record — the place it is most expensive.
    """
    events: List[tuple] = []
    monkeypatch.setattr(
        S19TuiApp,
        "_log_report_event",
        lambda self, *args, **kwargs: events.append((args, kwargs)),
    )

    def boom(*_args, **_kwargs):
        raise ValueError("injected")

    monkeypatch.setattr(app_module, "generate_project_report", boom)
    asyncio.run(_drive_worker(tmp_path))

    assert events, "the failure path logged nothing at all"
    flat = " ".join(str(a) for a in events)
    assert "failed:" in flat, f"the failure was not logged as a failure: {flat!r}"
    assert "rejected:" not in flat, (
        f"the durable log still blames the operator for a tool failure: {flat!r}"
    )


# ---------------------------------------------------------------------------
# AT-263 — PIN.
# ---------------------------------------------------------------------------


def test_at263_pin_progress_resets_to_zero_on_both_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-263 (PIN) — the bar is never left mid-fill, on either branch.

    ⚠ Labelled a PIN: both branches already reset progress on the base tree, so
    this cannot discriminate the change. It guards against the split introduced
    by LLR-110.1 dropping one of the resets.
    """

    def boom(*_args, **_kwargs):
        raise ValueError("injected")

    monkeypatch.setattr(app_module, "generate_project_report", boom)
    _statuses, failure_progress, _dir = asyncio.run(_drive_worker(tmp_path))
    assert failure_progress and failure_progress[-1] == 0, (
        f"progress left at {failure_progress[-1] if failure_progress else None} "
        f"on the tool-failure branch"
    )

    _statuses2, reject_progress, _dir2 = asyncio.run(
        _drive_worker(tmp_path, context_bytes=-1)
    )
    assert reject_progress and reject_progress[-1] == 0, (
        "progress left mid-fill on the operator-rejection branch"
    )


# ---------------------------------------------------------------------------
# TC-570 / TC-572 — the static properties.
# ---------------------------------------------------------------------------

#: Walked LEXICALLY, by name. "Reachable from" is not statically computable, and
#: a census that claims to compute it is asserting something it cannot.
_GUARDED_FUNCTIONS = ("_start_generate_report_worker",)


def _generation_inside_valueerror_span(source: str, function: str) -> List[int]:
    """Line numbers where ``generate_project_report`` is called inside a ``try``
    that catches ``ValueError``."""
    tree = ast.parse(source)
    target = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function
    )
    offenders: List[int] = []
    for node in ast.walk(target):
        if not isinstance(node, ast.Try):
            continue
        catches_value_error = any(
            isinstance(handler.type, ast.Name) and handler.type.id == "ValueError"
            for handler in node.handlers
        )
        if not catches_value_error:
            continue
        for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "generate_project_report"
            ):
                offenders.append(inner.lineno)
    return offenders


def test_tc570_generation_is_outside_every_valueerror_guarded_span() -> None:
    """TC-570 — LLR-110.1, asserted structurally rather than only behaviourally.

    ``AT-260`` observes the OUTCOME; this observes the STRUCTURE that produces
    it, so a future edit that re-nests the call is caught even if the injected
    fixture stops reaching the generator for some unrelated reason.
    """
    source = inspect.getsource(app_module)
    for function in _GUARDED_FUNCTIONS:
        offenders = _generation_inside_valueerror_span(source, function)
        assert not offenders, (
            f"{function}: generate_project_report is called at line(s) "
            f"{offenders} inside a try that catches ValueError — an internal "
            f"failure there is reported as operator-input rejection"
        )


def test_tc578_the_span_census_finds_a_planted_nesting() -> None:
    """TC-578 — positive control. A census that asserts an ABSENCE needs one.

    A walk that silently finds nothing is indistinguishable from a clean tree,
    which is how an emptiness assertion goes vacuous.
    """
    planted = (
        "def _start_generate_report_worker(self):\n"
        "    try:\n"
        "        report_path = generate_project_report(1, 2, 3)\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    found = _generation_inside_valueerror_span(planted, "_start_generate_report_worker")
    assert found, "the census walk is broken — it cannot see a planted nesting"


def test_tc572_the_tool_failure_sequence_exists_exactly_once() -> None:
    """TC-572 — LLR-110.2: one helper, not a copy in each handler.

    Duplicating the log/progress/status sequence is how two branches drift: one
    keeps its progress reset and the other loses it, and nothing notices because
    each branch is exercised by a different test.
    """
    source = inspect.getsource(app_module)
    worker = source[source.index("def _start_generate_report_worker") :]
    worker = worker[: worker.index("\n    def ")]

    # Extracted rather than inlined: a backslash escape inside an f-string is
    # Python 3.12+ syntax and this repo's ruff targets 3.8.
    built = worker.count('f"Report failed:')
    assert built == 1, (
        f"the tool-failure status is built {built} times; it must be built "
        f"once, in the shared helper"
    )
    assert worker.count("report_failed(exc)") == 2, (
        "the shared helper is not invoked by both handlers"
    )
    assert worker.count('f"Report rejected:') == 1
