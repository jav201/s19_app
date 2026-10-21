"""Batch-97 Flow Execution arms (HLR-147).

Inc-2 arms only: the service scope of LLR-147.5 (TC-B97-25 service arm) — the
11 strings of ``services/flow_execution_service.py`` that the flow screens
paint (A.2 ``ES_48_9C7BEAF``, scope ``flow_execution_service``). The module
constant ``flow_screens.py:235`` lands at Inc-5 and the ``FlowExecutionPanel``
scope at Inc-6, with the lane arms of TC-B97-21..26.

Two censuses over the service's string constants (docstrings excluded): (a)
``ES_MARKER`` and (b) the frozen values; a reach guard proves census (a) finds
exactly those 11 on ``9c7beaf``. A painted arm runs the service and matches
every block summary, diagnostic and finding against ``ES_MARKER``. Each test
names the mutation that turns it RED (PC-11: every clause is observable on
``main``).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

import pytest

from s19_app.tui.services.flow_execution_service import ChainSpec, run_chain_set, run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_WAITING,
    EXTERNAL_MODE_MANUAL,
    EXTERNAL_MODE_TERMINAL,
    ExternalStepBlock,
    ExternalStepConfirmation,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from tests.b97_fixtures import ES_48_9C7BEAF, ES_MARKER_RE, REPO_ROOT
from tests.b97_probes import string_constants
from tests.test_flow_funnel_b96 import _BASE16, _flow_blocks, _funnel_doc

SERVICE = "s19_app/tui/services/flow_execution_service.py"
SERVICE_SCOPE = "flow_execution_service"
FROZEN_SERVICE = [value for scope, value in ES_48_9C7BEAF if scope == SERVICE_SCOPE]
_S19 = "S107100001020304DE\nS9030000FC\n"


def _spanish(lines: List[str]) -> List[str]:
    return [line for line in lines if ES_MARKER_RE.search(line)]


def _project(tmp_path: Path, files: dict) -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    for name, text in files.items():
        (project_dir / name).write_text(text, encoding="utf-8")
    return project_dir


def _ext_spec(tmp_path: Path, mode: str = EXTERNAL_MODE_TERMINAL) -> ChainSpec:
    ext_dir = tmp_path / "ext"
    ext_dir.mkdir(exist_ok=True)
    block = ExternalStepBlock(
        mode=mode,
        instruction="python flash.py --release",
        log_ref="run.log",
        output_path=str(ext_dir / "flashed.s19"),
    )
    flow = Flow(name="ext", blocks=[SourceBlock("base.s19"), block, WriteOutBlock("out.s19")])
    return ChainSpec(name="ext", template="ext", flow=flow)


def _painted(record) -> List[str]:
    lines: List[str] = []
    for outcome in record.outcomes:
        for result in outcome.block_results:
            lines.append(result.summary)
            lines.extend(result.diagnostics)
            lines.extend(finding.message for finding in result.findings)
    return lines


def test_tc_b97_25_service_reach_guard_on_9c7beaf() -> None:
    """Census (a) on ``git show 9c7beaf:<service>`` returns exactly the 11
    frozen values, so a census that finds 0 on this tree is reaching the
    strings, not missing them.

    Reddening mutation: a census that skips f-string parts (``JoinedStr``)
    finds 5 of the 11 → RED.
    """
    try:
        source = subprocess.run(
            ["git", "show", f"9c7beaf:{SERVICE}"],
            cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 9c7beaf unavailable — reach guard cannot run: {exc}")
    found = [value for value in string_constants(source) if ES_MARKER_RE.search(value)]
    assert len(FROZEN_SERVICE) == 11
    assert sorted(found) == sorted(FROZEN_SERVICE), found


def test_tc_b97_25_service_constants_carry_no_spanish() -> None:
    """(a) 0 ``ES_MARKER`` constants and (b) 0 frozen values in the service.

    Reddening mutation: any one service string reverted to its Spanish value
    (e.g. ``"instruction"`` back to ``"instruccion"``) → both censuses RED.
    """
    constants = string_constants((REPO_ROOT / SERVICE).read_text(encoding="utf-8"))
    still_frozen = [value for value in FROZEN_SERVICE if value in constants]
    assert still_frozen == [], still_frozen
    assert _spanish(constants) == [], _spanish(constants)


@pytest.mark.parametrize(
    "mode,noun", [(EXTERNAL_MODE_TERMINAL, "command"), (EXTERNAL_MODE_MANUAL, "instruction")]
)
def test_tc_b97_25_pause_summary_in_english(tmp_path: Path, mode: str, noun: str) -> None:
    """The waiting summary names the step's noun, the pending LOG and OUTPUT
    once, in English.

    Reddening mutation: the noun kept as ``"comando"`` (the string the
    round-2 marker missed, LLR-147.5 NC) → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _S19})
    record = run_chain_set([_ext_spec(tmp_path, mode)], FlowContext(project_dir=project_dir))
    ext = record.outcomes[0].block_results[1]
    assert ext.status == BLOCK_STATUS_WAITING
    assert ext.summary.startswith(f"paused - waiting for a human: {noun} "), ext.summary
    assert ext.summary.count("pending") == 1, ext.summary
    assert _spanish(_painted(record)) == []


def test_tc_b97_25_confirm_and_refusal_lines_in_english(tmp_path: Path) -> None:
    """The confirm arms: a missing log, a missing output, then an accepted
    confirmation — every summary and diagnostic in English.

    Reddening mutation: the missing-output diagnostic reverted to
    ``"salida '…' no existe - correr el paso externo antes de confirmar"`` → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _S19})
    spec = _ext_spec(tmp_path)
    block = spec.flow.blocks[1]
    confirm = {
        1: ExternalStepConfirmation(
            block_index=1, log_ref=block.log_ref, source_path=block.output_path
        )
    }

    def run():
        return run_chain_set([spec], FlowContext(project_dir=project_dir, external_confirmations=confirm))

    no_log = run()
    assert no_log.outcomes[0].block_results[1].status == BLOCK_STATUS_ERROR
    assert any("mandatory evidence" in d for d in no_log.outcomes[0].block_results[1].diagnostics)

    (project_dir / "run.log").write_text("flashed OK\n", encoding="utf-8")
    no_output = run()
    assert any(
        "run the external step before confirming" in d
        for d in no_output.outcomes[0].block_results[1].diagnostics
    )

    Path(block.output_path).write_text(_S19, encoding="utf-8")
    done = run()
    ext = done.outcomes[0].block_results[1]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary == "log 'run.log' received · output copied to flashed.s19 (session)"
    assert _spanish(_painted(no_log) + _painted(no_output) + _painted(done)) == []


def test_tc_b97_25_funnel_notice_in_english(tmp_path: Path) -> None:
    """The undeclared-variable notice names the variable in English.

    Reddening mutation: the notice reverted to ``"… no declarada en el flow —
    el placeholder queda intacto"`` → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _BASE16, "ch.json": _funnel_doc()})
    flow = Flow(name="partial", blocks=_flow_blocks(), funnel=(("BOOST", "AB"),))
    result = run_flow(flow, FlowContext(project_dir=project_dir))
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_NOTICES
    messages = [finding.message for finding in patch.findings]
    assert messages == [
        "funnel: ${MISSING} is not declared in the flow — the placeholder stays intact"
    ], messages
