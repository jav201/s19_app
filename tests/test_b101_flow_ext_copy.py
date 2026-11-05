"""Batch-101 Inc 8 (G2) — a later block reads this run's external-step copy.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-8/01-requirements.md``
rows R-FLOW-EXT.2, .9, .10, .11, .12, .13, .14 and R-FLOW-CRC.3, .4, .9 —
one test per case of ``inc-8/02-test-cases.md``. The flow-X fixture and the
Doc(v) change document are exactly the common fixtures of that table. The
Flow-Execution case (R-FLOW-EXT.9/11) drives the shipped TUI through keys
with a Textual pilot. No source file is edited here.

Traceability (E4): test names start ``test_r_<row id>_…`` so the registry
binds them; no AT-/TC- tokens.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.operations import crc_config as crc_config_module
from s19_app.tui.operations.crc_designer_model import emit_template, seed_template
from s19_app.tui.services import flow_execution_service as fes
from s19_app.tui.services.flow_execution_service import (
    CHAIN_RUN_SEQUENTIAL,
    ChainSpec,
    compose_chain_set_report,
    run_chain_set,
    run_flow,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    EXTERNAL_MODE_TERMINAL,
    A2BBlock,
    A2BInputBinding,
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    ExternalStepConfirmation,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.markdown_safety import md_safe

# --- flow X (the 18.9 case, shrunk) — inc-8/02-test-cases.md common fixtures --
_S19_SRC = "S107100001020304DE\nS9030000FC\n"  # 01 02 03 04 at 0x1000
_READ_SUFFIX = " · read {copy} in place of {ref}"
_TEMPLATE_REASON = (
    "a CRC Designer template is not a CRC config - it has no regions or groups"
)


def _project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        target = project_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return project_dir


def _bench(tmp_path: Path) -> Path:
    bench = tmp_path / "bench"
    bench.mkdir(exist_ok=True)
    return bench


def _doc(value: str, address: int = 0x1000, kind: str = "change") -> str:
    """Doc(v): one `string` entry, value v, at `address` (text mode)."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "string", "address": f"0x{address:08X}", "value": value}
            ],
        }
    )


def _bytes_doc(
    entries: list[tuple[int, str]], kind: str = "change"
) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "bytes", "address": f"0x{address:08X}", "bytes": run}
                for address, run in entries
            ],
        }
    )


def _ext_block(bench: Path, log: str, output: str) -> ExternalStepBlock:
    return ExternalStepBlock(
        mode=EXTERNAL_MODE_TERMINAL,
        instruction="python tool.py --release",
        log_ref=log,
        output_path=output,
    )


def _flow_x(
    bench: Path,
    *,
    log: str | None = None,
    output: str | None = None,
    patch_ref: str = "step.changes.json",
    patch_a2l_ref: str | None = None,
    write_out: str = "out.s19",
    extra_blocks: tuple = (),
) -> Flow:
    """LOAD base.s19 → EXT-STEP → PATCH step.changes.json → WRITE-OUT out.s19
    (with `extra_blocks` spliced between the PATCH and the WRITE-OUT)."""
    log = log if log is not None else str(bench / "step.log")
    output = output if output is not None else str(bench / "step.changes.json")
    return Flow(
        name="flow_x",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, log, output),
            PatchBlock(patch_ref, a2l_ref=patch_a2l_ref),
            *extra_blocks,
            WriteOutBlock(write_out),
        ],
    )


def _write_bench(bench: Path, text: str, name: str = "step.changes.json") -> None:
    (bench / "step.log").write_text("tool ran OK\n", encoding="utf-8")
    (bench / name).write_text(text, encoding="utf-8")


def _confirm(
    bench: Path, index: int = 1, output: str = "step.changes.json", log: str | None = None
):
    return {
        index: ExternalStepConfirmation(
            block_index=index,
            log_ref=log if log is not None else str(bench / "step.log"),
            source_path=str(bench / output),
        )
    }


def _run(flow: Flow, project: Path, confirmations) -> object:
    return run_flow(flow, FlowContext(project_dir=project, external_confirmations=confirmations))


def _reload_mem(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


def _cause(block) -> str:
    """The user-facing cause is the LAST diagnostic line (UX-C2)."""
    assert block.diagnostics, block
    return block.diagnostics[-1]


def _a2l_text(address: int) -> str:
    """A minimal A2L placing `Speed` at `address` (the proven fixture shape)."""
    return (
        "/begin PROJECT P\n"
        "/begin MODULE M\n"
        "/begin MEASUREMENT Speed\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        f"ECU_ADDRESS 0x{address:08X}\n"
        "/end MEASUREMENT\n"
        "/end MODULE\n"
        "/end PROJECT\n"
    )


def _crc_config_text(output_address: int, *, reverse: bool = True) -> str:
    return json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": reverse,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {
                    "start": "0x1000",
                    "end": "0x1004",
                    "output_address": f"0x{output_address:X}",
                }
            ],
        }
    )


# ---------------------------------------------------------------------------
# R-FLOW-EXT.2 — relative log/output paths read under the project folder
# ---------------------------------------------------------------------------


def test_r_flow_ext_2_1_relative_log_read_under_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative log found only under the project is read while the working
    directory is elsewhere (holds on base — the log join is not the fix)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "logs").mkdir()
    (project / "logs" / "step.log").write_text("tool ran OK\n", encoding="utf-8")
    bench = _bench(tmp_path)
    (bench / "step.changes.json").write_text(_doc("AA"), encoding="utf-8")
    flow = _flow_x(bench, log="logs/step.log")
    monkeypatch.chdir(tmp_path)

    result = _run(flow, project, _confirm(bench, log="logs/step.log"))

    ext = result.block_results[1]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary.startswith("log 'step.log' received"), ext.summary


def test_r_flow_ext_2_2_relative_output_read_under_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """[D15-17] A relative output found only under the project is read under
    the project (base reads it against the working directory → refuses)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "bench").mkdir()
    (project / "bench" / "rel.changes.json").write_text(_doc("AA"), encoding="utf-8")
    bench = _bench(tmp_path)
    (bench / "step.log").write_text("tool ran OK\n", encoding="utf-8")
    flow = _flow_x(bench, output="bench/rel.changes.json")
    monkeypatch.chdir(tmp_path)

    result = _run(
        flow,
        project,
        {1: ExternalStepConfirmation(1, str(bench / "step.log"), "bench/rel.changes.json")},
    )

    ext = result.block_results[1]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary == (
        "log 'step.log' received · output copied to rel.changes.json (session)"
    ), ext.summary


# ---------------------------------------------------------------------------
# R-FLOW-EXT.9 — a later block reads this run's copy
# ---------------------------------------------------------------------------


def _two_runs_flow_x(tmp_path: Path):
    """Run 1 with Doc(AA) done; return (project, bench, flow) for run 2."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("AA"))
    flow = _flow_x(bench)
    first = _run(flow, project, _confirm(bench))
    assert first.block_results[1].summary.endswith(
        "output copied to step.changes.json (session)"
    ), first.block_results[1].summary
    return project, bench, flow


def test_r_flow_ext_9_1_later_patch_reads_this_runs_copy(tmp_path: Path) -> None:
    """[F-49] Run 2's differing output is copied as _1 and the later PATCH
    reads the copy (base keeps the first copy's bytes)."""
    project, bench, flow = _two_runs_flow_x(tmp_path)
    _write_bench(bench, _doc("BB"))

    result = _run(flow, project, _confirm(bench))

    ext, patch = result.block_results[1], result.block_results[2]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary == (
        "log 'step.log' received · output copied to step.changes_1.json (session)"
    ), ext.summary
    assert patch.status == BLOCK_STATUS_OK
    assert patch.summary == (
        "applied 1 entry"
        + _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
    ), patch.summary
    assert [(entry.block_index, entry.change_doc_ref) for entry in result.in_place_reads] == [
        (2, "step.changes_1.json")
    ]
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x42, 0x42]


def test_r_flow_ext_9_2_first_run_reads_the_plain_copy(tmp_path: Path) -> None:
    """A first run into an empty folder: the copy lands under the output file
    name and is read as usual (holds on base — the rebind pins nothing new)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("AA"))
    flow = _flow_x(bench)

    result = _run(flow, project, _confirm(bench))

    assert result.block_results[1].summary.endswith(
        "output copied to step.changes.json (session)"
    )
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x41, 0x41]


def test_r_flow_ext_9_3_reused_copy_is_read(tmp_path: Path) -> None:
    """Run 3 repeats run 1's output: the byte-identical earlier copy is reused
    under the output file name (holds on base — placement reuse)."""
    project, bench, flow = _two_runs_flow_x(tmp_path)
    _write_bench(bench, _doc("BB"))
    second = _run(flow, project, _confirm(bench))
    assert second.block_results[1].summary.endswith(
        "output copied to step.changes_1.json (session)"
    )
    _write_bench(bench, _doc("AA"))

    third = _run(flow, project, _confirm(bench))

    assert third.block_results[1].summary.endswith(
        "output copied to step.changes.json (session)"
    ), third.block_results[1].summary
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x41, 0x41]


def _check_flow(bench: Path, check_output: str = "step.chk.json") -> Flow:
    return Flow(
        name="check_flow",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / check_output)),
            CheckBlock(check_output),
            WriteOutBlock("out.s19"),
        ],
    )


def test_r_flow_ext_9_4_later_check_block(tmp_path: Path) -> None:
    """Run 2's CHECK reads the copy: the new expectation fails 1 entry (base
    checks the first document: 0 failed)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _bytes_doc([(0x1000, "01 02")], kind="check"), "step.chk.json")
    flow = _check_flow(bench)
    first = _run(flow, project, _confirm(bench, output="step.chk.json"))
    assert "failed=0" in first.block_results[2].summary
    _write_bench(bench, _bytes_doc([(0x1000, "FF FF")], kind="check"), "step.chk.json")

    second = _run(flow, project, _confirm(bench, output="step.chk.json"))

    check = second.block_results[2]
    assert check.status == BLOCK_STATUS_NOTICES
    assert "failed=1" in check.summary, check.summary


def _crc_flow(bench: Path, config_name: str = "step.crc.json") -> Flow:
    return Flow(
        name="crc_flow",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / config_name)),
            CrcBlock(config_name),
            WriteOutBlock("out.s19"),
        ],
    )


def test_r_flow_ext_9_5_later_crc_block(tmp_path: Path) -> None:
    """Run 2's CRC block reads the copy: 4 CRC bytes at the NEW output address
    and none at the old one."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _crc_config_text(0x1010), "step.crc.json")
    flow = _crc_flow(bench)
    first = _run(flow, project, _confirm(bench, output="step.crc.json"))
    assert first.status == "ok"
    _write_bench(bench, _crc_config_text(0x1020), "step.crc.json")

    second = _run(flow, project, _confirm(bench, output="step.crc.json"))

    mem = _reload_mem(project / "out.s19")
    assert all(0x1020 + i in mem for i in range(4)), hex(0x1020)
    assert 0x1010 not in mem, "no CRC bytes at the run-1 output address"


def test_r_flow_ext_9_6_later_load_block(tmp_path: Path) -> None:
    """Run 2's LOAD reads the copy: out.s19 holds image B's bytes."""
    image_a = emit_s19_from_mem_map({0x1000: 0x01, 0x1001: 0x02}, [(0x1000, 0x1002)])
    image_b = emit_s19_from_mem_map({0x1000: 0x09, 0x1001: 0x08}, [(0x1000, 0x1002)])
    project = _project(tmp_path, {})
    bench = _bench(tmp_path)
    _write_bench(bench, image_a, "fw.s19")
    flow = Flow(
        name="load_flow",
        blocks=[
            _ext_block(bench, str(bench / "step.log"), str(bench / "fw.s19")),
            SourceBlock("fw.s19"),
            WriteOutBlock("out.s19"),
        ],
    )
    first = _run(flow, project, _confirm(bench, index=0, output="fw.s19"))
    assert first.status == "ok"
    _write_bench(bench, image_b, "fw.s19")

    second = _run(flow, project, _confirm(bench, index=0, output="fw.s19"))

    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x09, 0x08]


def test_r_flow_ext_9_7_later_a2b_file_input(tmp_path: Path) -> None:
    """Run 2's A2B file input reads the copy: the report lists the difference
    at 0x00001000 (run 1: none)."""
    same = emit_s19_from_mem_map({0x1000: 0x01, 0x1001: 0x02}, [(0x1000, 0x1002)])
    different = emit_s19_from_mem_map({0x1000: 0x09, 0x1001: 0x02}, [(0x1000, 0x1002)])
    project = _project(tmp_path, {"base.s19": same})
    bench = _bench(tmp_path)
    _write_bench(bench, same, "ext.s19")
    flow = Flow(
        name="a2b_flow",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "ext.s19")),
            A2BBlock(
                image_a=A2BInputBinding(source=A2B_INPUT_FLOW, ref="0"),
                image_b=A2BInputBinding(source=A2B_INPUT_FILE, ref="ext.s19"),
            ),
        ],
    )
    first = _run(flow, project, _confirm(bench, output="ext.s19"))
    reports_dir = project / "reports"
    first_reports = set(reports_dir.glob("*")) if reports_dir.exists() else set()
    assert first.status == "ok"
    _write_bench(bench, different, "ext.s19")

    second = _run(flow, project, _confirm(bench, output="ext.s19"))

    new_reports = [
        path for path in reports_dir.glob("*") if path not in first_reports
    ]
    assert len(new_reports) == 1, new_reports
    text = new_reports[0].read_text(encoding="utf-8")
    assert "0x00001000" in text, text


def test_r_flow_ext_9_8_other_refs_unchanged(tmp_path: Path) -> None:
    """A ref that names another file is not read in place: the second PATCH
    applies `patches/other.changes.json` (holds on base; the rebind is by the
    output file name only)."""
    project, bench, flow = _two_runs_flow_x(tmp_path)
    (project / "patches").mkdir()
    (project / "patches" / "other.changes.json").write_text(
        _doc("EE"), encoding="utf-8"
    )
    flow = Flow(
        name="flow_x",
        blocks=[
            *flow.blocks[:3],
            PatchBlock("patches/other.changes.json"),
            flow.blocks[-1],
        ],
    )
    _write_bench(bench, _doc("BB"))

    result = _run(flow, project, _confirm(bench))

    first_patch, second_patch = result.block_results[2], result.block_results[3]
    assert first_patch.summary.endswith(
        _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
    ), first_patch.summary
    assert second_patch.summary == "applied 1 entry", second_patch.summary
    records = [c for c in result.change_records if c.block_index == 3]
    assert records and records[0].change_doc_ref == "patches/other.changes.json"
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x45, 0x45]


def test_r_flow_ext_9_9_earlier_block_reads_the_file_as_it_is(tmp_path: Path) -> None:
    """A block BEFORE the step reads the file as it is: run 2's first PATCH
    sees the run-1 copy (AA), the second sees this run's (BB)."""
    project, bench, _ = _two_runs_flow_x(tmp_path)
    flow = Flow(
        name="reordered",
        blocks=[
            SourceBlock("base.s19"),
            PatchBlock("step.changes.json"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "step.changes.json")),
            PatchBlock("step.changes.json"),
            WriteOutBlock("out.s19"),
        ],
    )
    _write_bench(bench, _doc("BB"))

    result = _run(flow, project, _confirm(bench, index=2))

    first_patch, second_patch = result.block_results[1], result.block_results[3]
    assert first_patch.summary == "applied 1 entry", first_patch.summary
    early = [c for c in result.change_records if c.block_index == 1]
    late = [c for c in result.change_records if c.block_index == 3]
    assert early and early[0].after_bytes[0:2] == [0x41, 0x41], early
    assert late and late[0].after_bytes[0:2] == [0x42, 0x42], late
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x42, 0x42]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="case rule: Windows")
def test_r_flow_ext_9_10_case_insensitive_on_windows(tmp_path: Path) -> None:
    """A ref spelling the output file name case-differently is read in place
    on Windows (the name comparison is case-insensitive)."""
    project, bench, _ = _two_runs_flow_x(tmp_path)
    flow = _flow_x(bench, patch_ref="STEP.CHANGES.JSON")
    _write_bench(bench, _doc("BB"))

    result = _run(flow, project, _confirm(bench))

    patch = result.block_results[2]
    assert patch.summary.endswith(
        _READ_SUFFIX.format(copy="step.changes_1.json", ref="STEP.CHANGES.JSON")
    ), patch.summary
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x42, 0x42]


# ---------------------------------------------------------------------------
# R-FLOW-EXT.9/11 — the 18.9 path through Flow Execution (black box, keys)
# ---------------------------------------------------------------------------


def test_r_flow_ext_9_11_flow_execution_confirm_reads_new_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lane is confirmed against BENCH=OK; the bench output is rewritten
    with BENCH=V2; Run then `c` re-runs the lane and terminal_out.s19 holds
    BENCH=V2 at 0x00C001B0 (base: the PATCH re-applies the first copy)."""
    from tests.b97_fixtures import (
        load_project,
        open_flow_execution,
        run_lanes,
        import_lanes,
        write_flow,
    )
    from tests.b97_probes import settle

    base_text = emit_s19_from_mem_map(
        {0x00C001B0 + i: byte for i, byte in enumerate(b"BENCH=OK")},
        [(0x00C001B0, 0x00C001B8)],
    )
    bench = _bench(tmp_path)

    async def _drive() -> bytes:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            project_dir = app.workarea / "demo"
            project_dir.mkdir(parents=True, exist_ok=True)
            (project_dir / "base.s19").write_text(base_text, encoding="utf-8")
            write_flow(
                project_dir,
                "terminal",
                [
                    SourceBlock("base.s19"),
                    _ext_block(bench, str(bench / "step.log"), str(bench / "step.changes.json")),
                    PatchBlock("step.changes.json"),
                    WriteOutBlock("terminal_out.s19"),
                ],
            )
            await load_project(app, "demo")
            panel = await open_flow_execution(app, pilot)
            await import_lanes(app, pilot, "terminal")
            _write_bench(bench, _doc("BENCH=OK", address=0x00C001B0))
            await run_lanes(app, pilot, panel, key=True)
            await pilot.press("c")  # confirm run 1 (BENCH=OK)
            for _ in range(300):
                await pilot.pause()
                if (project_dir / "terminal_out.s19").exists():
                    break
            assert (project_dir / "terminal_out.s19").exists(), "run 1 never finished"
            first = _reload_mem(project_dir / "terminal_out.s19")
            assert [first[0x00C001B0 + i] for i in range(8)] == list(b"BENCH=OK")
            # the bench output now holds the NEW evidence
            _write_bench(bench, _doc("BENCH=V2", address=0x00C001B0))
            await run_lanes(app, pilot, panel, key=True)
            await pilot.press("c")
            for _ in range(300):
                await pilot.pause()
                if (project_dir / "step.changes_1.json").exists():
                    break
            assert (project_dir / "step.changes_1.json").exists(), (
                "run 2 never copied the new output"
            )
            await settle(pilot, 6)
            return bytes(
                _reload_mem(project_dir / "terminal_out.s19")[0x00C001B0 + i]
                for i in range(8)
            )

    assert asyncio.run(_drive()) == b"BENCH=V2"


def test_r_flow_ext_9_12_later_a2l_ref(tmp_path: Path) -> None:
    """Run 2's PATCH resolves its symbol entry against the copied A2L: the
    change record address is the v2 address 0x1002."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _a2l_text(0x1000), "cal.a2l")
    (project / "step.changes.json").write_text(_symbol_doc(), encoding="utf-8")
    flow = Flow(
        name="a2l_flow",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "cal.a2l")),
            PatchBlock("step.changes.json", a2l_ref="cal.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )
    first = _run(flow, project, _confirm(bench, output="cal.a2l"))
    assert first.status == "ok"
    record = [c for c in first.change_records if c.block_index == 2]
    assert record and record[0].address_start == 0x1000
    _write_bench(bench, _a2l_text(0x1002), "cal.a2l")

    second = _run(flow, project, _confirm(bench, output="cal.a2l"))

    record = [c for c in second.change_records if c.block_index == 2]
    assert record and record[0].address_start == 0x1002, record


def test_r_flow_ext_9_13_first_run_over_a_foreign_file_reads_the_copy(tmp_path: Path):
    """[A-2] A first run into a folder that already holds a DIFFERENT file
    under the output file name: the copy lands _1 and the PATCH reads the
    copy (base applies the foreign file's bytes)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "step.changes.json").write_text(_doc("CC"), encoding="utf-8")
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("AA"))
    flow = _flow_x(bench)

    result = _run(flow, project, _confirm(bench))

    ext, patch = result.block_results[1], result.block_results[2]
    assert ext.summary.endswith("output copied to step.changes_1.json (session)"), (
        ext.summary
    )
    assert patch.summary == (
        "applied 1 entry"
        + _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
    ), patch.summary
    mem = _reload_mem(project / "out.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x41, 0x41]
    # the foreign file under the output file name keeps its bytes
    assert (project / "step.changes.json").read_bytes() == _doc("CC").encode("utf-8")


def test_r_flow_ext_9_14_other_chain_is_not_rebound(tmp_path: Path) -> None:
    """[A-8] A ref of another chain of the same set is never read in place:
    chain B's PATCH applies the file that was there (holds on base)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "step.changes.json").write_text(_doc("AA"), encoding="utf-8")
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("BB"))
    chain_a = ChainSpec(
        name="lane_a",
        template="lane_a",
        flow=Flow(
            name="lane_a",
            blocks=[
                SourceBlock("base.s19"),
                _ext_block(bench, str(bench / "step.log"), str(bench / "step.changes.json")),
                WriteOutBlock("out.s19"),
            ],
        ),
    )
    chain_b = ChainSpec(
        name="lane_b",
        template="lane_b",
        flow=Flow(
            name="lane_b",
            blocks=[
                SourceBlock("base.s19"),
                PatchBlock("step.changes.json"),
                WriteOutBlock("b.s19"),
            ],
        ),
    )

    record = run_chain_set(
        [chain_a, chain_b],
        FlowContext(project_dir=project, external_confirmations=_confirm(bench, index=1)),
        mode=CHAIN_RUN_SEQUENTIAL,
    )

    assert record.outcomes[0].block_results[1].summary.endswith(
        "output copied to step.changes_1.json (session)"
    )
    patch_b = record.outcomes[1].block_results[1]
    assert patch_b.summary == "applied 1 entry", patch_b.summary
    mem = _reload_mem(project / "b.s19")
    assert [mem[0x1000 + i] for i in range(2)] == [0x41, 0x41]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="the junction half is Windows")
def test_r_flow_ext_9_15_refused_ref_stays_refused_after_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """[S-4] After a rebind, (a) an absolute ref and (b) a junction ref that
    name the output file name are still refused by the manifest guard (holds
    on base — the guard ran first there too; the case pins the order)."""
    from tests.b97_fixtures import make_junction

    cwd = Path.cwd()
    try:
        monkeypatch.chdir(tmp_path)
        # (a) the absolute ref
        project = _project(tmp_path, {"base.s19": _S19_SRC}, name="proj_a")
        bench_a = tmp_path / "bench_a"
        bench_a.mkdir(exist_ok=True)
        _write_bench(bench_a, _doc("AA"))
        run_flow(
            _flow_x(bench_a),
            FlowContext(project_dir=project, external_confirmations=_confirm(bench_a)),
        )
        _write_bench(bench_a, _doc("BB"))
        result_a = _run(
            _flow_x(bench_a, patch_ref=str(project / "step.changes.json")),
            project,
            _confirm(bench_a),
        )
        patch_a = result_a.block_results[2]
        assert patch_a.status == BLOCK_STATUS_ERROR
        assert patch_a.summary == "change doc unresolved", patch_a.summary
        assert _cause(patch_a) == "change document not found or not inside the project"
        escape_a = [d for d in patch_a.diagnostics if d.startswith("[MANIFEST-PATH-ESCAPE]")]
        assert len(escape_a) == 1, patch_a.diagnostics
        assert result_a.block_results[3].status == BLOCK_STATUS_SKIPPED
        assert str(project / "out.s19") not in [str(p) for p in result_a.written_paths]

        # (b) the junction ref
        project_b = _project(tmp_path, {"base.s19": _S19_SRC}, name="proj_b")
        bench_b = tmp_path / "bench_b"
        bench_b.mkdir(exist_ok=True)
        _write_bench(bench_b, _doc("AA"))
        run_flow(
            _flow_x(bench_b),
            FlowContext(project_dir=project_b, external_confirmations=_confirm(bench_b)),
        )
        make_junction(project_b / "jl", project_b)
        _write_bench(bench_b, _doc("BB"))
        result_b = _run(
            _flow_x(bench_b, patch_ref="jl/step.changes.json"),
            project_b,
            _confirm(bench_b),
        )
        patch_b = result_b.block_results[2]
        assert patch_b.status == BLOCK_STATUS_ERROR
        assert patch_b.summary == "change doc unresolved", patch_b.summary
        assert _cause(patch_b) == "change document not found or not inside the project"
        escape_b = [d for d in patch_b.diagnostics if d.startswith("[MANIFEST-PATH-ESCAPE]")]
        assert len(escape_b) == 1, patch_b.diagnostics
        assert result_b.block_results[3].status == BLOCK_STATUS_SKIPPED
        assert str(project_b / "out.s19") not in [str(p) for p in result_b.written_paths]
    finally:
        monkeypatch.chdir(cwd)


# ---------------------------------------------------------------------------
# R-FLOW-EXT.10 — reports name the copy
# ---------------------------------------------------------------------------


def _report_snapshot(project: Path) -> set[Path]:
    reports_dir = project / "reports"
    return set(reports_dir.glob("*.md")) if reports_dir.exists() else set()


def _new_flow_report(project: Path, before: set[Path]) -> str:
    new = _report_snapshot(project) - before
    assert len(new) == 1, f"expected exactly one new report, got {new}"
    return new.pop().read_text(encoding="utf-8")


def test_r_flow_ext_10_1_flow_report_names_the_copy(tmp_path: Path) -> None:
    """The flow report's Change attribution row names the copy."""
    project, bench, _ = _two_runs_flow_x(tmp_path)
    flow = Flow(
        name="flow_x",
        blocks=[*(_flow_x(bench).blocks[:-1]), ReportBlock()],
    )
    _write_bench(bench, _doc("BB"))

    before = _report_snapshot(project)
    result = _run(flow, project, _confirm(bench))

    record = [c for c in result.change_records if c.block_index == 2]
    assert record and record[0].change_doc_ref == "step.changes_1.json"
    text = _new_flow_report(project, before)
    assert "## Change attribution" in text
    section = text.split("## Change attribution")[1].split("## Not applied")[0]
    assert md_safe("step.changes_1.json", limit=120) in section, section
    assert "step\\.changes_1.json" in section or "step.changes_1.json" in section


def test_r_flow_ext_10_2_chain_set_report_names_the_copy(tmp_path: Path) -> None:
    """The chain-set report's Not applied line carries the copy name."""
    project, bench, _ = _two_runs_flow_x(tmp_path)
    _write_bench(
        bench,
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {"type": "string", "address": "0x00001000", "value": "BB"},
                    {"type": "string", "address": "0x00009000", "value": "ZZ"},
                ],
            }
        ),
    )
    chain = ChainSpec(
        name="lane1",
        template="lane1",
        flow=_flow_x(bench),
    )

    record = run_chain_set(
        [chain],
        FlowContext(project_dir=project, external_confirmations=_confirm(bench)),
        mode=CHAIN_RUN_SEQUENTIAL,
    )

    outcome = record.outcomes[0]
    assert outcome.status in ("ok", "completed-with-issues")
    text = record.report_path.read_text(encoding="utf-8")
    not_applied = text.split("## Not applied")[1].split("## Refusals")[0]
    lines = [
        ln
        for ln in not_applied.splitlines()
        if ln.startswith("- Chain ") and "0x00009000" in ln
    ]
    assert len(lines) == 1, not_applied
    assert lines[0].endswith("(step.changes_1.json)"), lines[0]


def test_r_flow_ext_10_3_unbound_ref_kept_as_typed(tmp_path: Path) -> None:
    """A ref that resolves to the copy itself keeps its typed text (holds on
    base — no rebind happens)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("AA"))
    flow = Flow(
        name="flow_x",
        blocks=[
            *(_flow_x(bench, patch_ref="./step.changes.json").blocks[:-1]),
            ReportBlock(),
        ],
    )

    before = _report_snapshot(project)
    result = _run(flow, project, _confirm(bench))

    record = [c for c in result.change_records if c.block_index == 2]
    assert record and record[0].change_doc_ref == "./step.changes.json"
    text = _new_flow_report(project, before)
    section = text.split("## Change attribution")[1].split("## Not applied")[0]
    assert md_safe("./step.changes.json", limit=120) in section, section


def _a2l_patch_flow(bench: Path, *, load_declares: bool, write_out: str = "out.s19") -> Flow:
    """EXT (output cal.a2l) → LOAD (optionally declaring cal.a2l) → PATCH
    (symbol entry, own or inherited A2L) → WRITE-OUT."""
    patch = PatchBlock("doc.json", a2l_ref=None if load_declares else "cal.a2l")
    source = (
        SourceBlock("base.s19", a2l_ref="cal.a2l")
        if load_declares
        else SourceBlock("base.s19")
    )
    return Flow(
        name="a2l_report",
        blocks=[
            _ext_block(bench, str(bench / "step.log"), str(bench / "cal.a2l")),
            source,
            patch,
            WriteOutBlock(write_out),
        ],
    )


def _symbol_doc() -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {
                    "type": "bytes",
                    "address": "0x00001000",
                    "bytes": "AA",
                    "symbol": "Speed",
                }
            ],
        }
    )


def test_r_flow_ext_10_4_flow_report_names_the_copy_a2l_own(tmp_path: Path) -> None:
    """[A-1] The flow report's A2L reference cell names the PATCH's own A2L
    copy (base: the typed ref)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC, "doc.json": _symbol_doc()})
    bench = _bench(tmp_path)
    _write_bench(bench, _a2l_text(0x1000), "cal.a2l")
    flow = Flow(
        name="a2l_report",
        blocks=[
            *(_a2l_patch_flow(bench, load_declares=False).blocks),
            ReportBlock(),
        ],
    )
    first = _run(flow, project, _confirm(bench, index=0, output="cal.a2l"))
    assert first.status == "ok"
    before = _report_snapshot(project)
    _write_bench(bench, _a2l_text(0x1002), "cal.a2l")

    second = _run(flow, project, _confirm(bench, index=0, output="cal.a2l"))

    record = [c for c in second.change_records if c.block_index == 2]
    assert record and record[0].a2l_ref == "cal_1.a2l", record
    text = _new_flow_report(project, before)
    section = text.split("## Change attribution")[1].split("## Not applied")[0]
    assert md_safe("cal_1.a2l", limit=120) in section, section


def test_r_flow_ext_10_5_flow_report_names_the_copy_a2l_inherited(tmp_path: Path) -> None:
    """[A-1] The PATCH inherits the LOAD's A2L: the record and the report
    name the inherited copy; the LOAD summary carries the read suffix."""
    project = _project(tmp_path, {"base.s19": _S19_SRC, "doc.json": _symbol_doc()})
    bench = _bench(tmp_path)
    _write_bench(bench, _a2l_text(0x1000), "cal.a2l")
    flow = Flow(
        name="a2l_report",
        blocks=[
            *(_a2l_patch_flow(bench, load_declares=True).blocks),
            ReportBlock(),
        ],
    )
    first = _run(flow, project, _confirm(bench, index=0, output="cal.a2l"))
    assert first.status == "ok"
    before = _report_snapshot(project)
    _write_bench(bench, _a2l_text(0x1002), "cal.a2l")

    second = _run(flow, project, _confirm(bench, index=0, output="cal.a2l"))

    load_block = second.block_results[1]
    assert load_block.summary.endswith(
        _READ_SUFFIX.format(copy="cal_1.a2l", ref="cal.a2l")
    ), load_block.summary
    record = [c for c in second.change_records if c.block_index == 2]
    assert record and record[0].a2l_ref == "cal_1.a2l", record
    text = _new_flow_report(project, before)
    section = text.split("## Change attribution")[1].split("## Not applied")[0]
    assert md_safe("cal_1.a2l", limit=120) in section, section


# ---------------------------------------------------------------------------
# R-FLOW-EXT.12 — the block summary ends with the read suffix
# ---------------------------------------------------------------------------


def test_r_flow_ext_12_1_summary_names_the_copy_patch(tmp_path: Path) -> None:
    project, bench, flow = _two_runs_flow_x(tmp_path)
    _write_bench(bench, _doc("BB"))
    result = _run(flow, project, _confirm(bench))
    assert result.block_results[2].summary == (
        "applied 1 entry"
        + _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
    )


def test_r_flow_ext_12_2_summary_names_the_copy_check(tmp_path: Path) -> None:
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _bytes_doc([(0x1000, "01 02")], kind="check"), "step.chk.json")
    flow = _check_flow(bench)
    _run(flow, project, _confirm(bench, output="step.chk.json"))
    _write_bench(bench, _bytes_doc([(0x1000, "FF FF")], kind="check"), "step.chk.json")
    result = _run(flow, project, _confirm(bench, output="step.chk.json"))
    assert result.block_results[2].summary == (
        "passed=0 failed=1 uncheckable=0"
        + _READ_SUFFIX.format(copy="step_1.chk.json", ref="step.chk.json")
    ), result.block_results[2].summary


def test_r_flow_ext_12_3_summary_names_the_copy_crc(tmp_path: Path) -> None:
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _crc_config_text(0x1010), "step.crc.json")
    flow = _crc_flow(bench)
    _run(flow, project, _confirm(bench, output="step.crc.json"))
    _write_bench(bench, _crc_config_text(0x1020), "step.crc.json")
    result = _run(flow, project, _confirm(bench, output="step.crc.json"))
    assert result.block_results[2].summary == (
        "injected 1 CRC region"
        + _READ_SUFFIX.format(copy="step_1.crc.json", ref="step.crc.json")
    ), result.block_results[2].summary


def test_r_flow_ext_12_4_summary_names_the_copy_load(tmp_path: Path) -> None:
    image_a = emit_s19_from_mem_map({0x1000: 0x01}, [(0x1000, 0x1001)])
    image_b = emit_s19_from_mem_map({0x1000: 0x09}, [(0x1000, 0x1001)])
    project = _project(tmp_path, {})
    bench = _bench(tmp_path)
    _write_bench(bench, image_a, "fw.s19")
    flow = Flow(
        name="load_flow",
        blocks=[
            _ext_block(bench, str(bench / "step.log"), str(bench / "fw.s19")),
            SourceBlock("fw.s19"),
            WriteOutBlock("out.s19"),
        ],
    )
    _run(flow, project, _confirm(bench, index=0, output="fw.s19"))
    _write_bench(bench, image_b, "fw.s19")
    result = _run(flow, project, _confirm(bench, index=0, output="fw.s19"))
    assert result.block_results[1].summary == (
        "loaded fw_1.s19 (1 ranges)"
        + _READ_SUFFIX.format(copy="fw_1.s19", ref="fw.s19")
    ), result.block_results[1].summary


def test_r_flow_ext_12_5_summary_names_the_copy_a2b(tmp_path: Path) -> None:
    same = emit_s19_from_mem_map({0x1000: 0x01}, [(0x1000, 0x1001)])
    different = emit_s19_from_mem_map({0x1000: 0x09}, [(0x1000, 0x1001)])
    project = _project(tmp_path, {"base.s19": same})
    bench = _bench(tmp_path)
    _write_bench(bench, same, "ext.s19")
    flow = Flow(
        name="a2b_flow",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "ext.s19")),
            A2BBlock(
                image_a=A2BInputBinding(source=A2B_INPUT_FLOW, ref="0"),
                image_b=A2BInputBinding(source=A2B_INPUT_FILE, ref="ext.s19"),
            ),
        ],
    )
    _run(flow, project, _confirm(bench, output="ext.s19"))
    _write_bench(bench, different, "ext.s19")
    result = _run(flow, project, _confirm(bench, output="ext.s19"))
    summary = result.block_results[2].summary
    assert summary.startswith("wrote reports/"), summary
    assert summary.endswith(
        _READ_SUFFIX.format(copy="ext_1.s19", ref="ext.s19")
    ), summary


def test_r_flow_ext_12_6_summary_names_the_copy_error(tmp_path: Path) -> None:
    """An error summary carries the suffix too (the config in the copied
    output is malformed: no `reverse`)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _crc_config_text(0x1010), "step.crc.json")
    flow = _crc_flow(bench)
    _run(flow, project, _confirm(bench, output="step.crc.json"))
    bad = json.loads(_crc_config_text(0x1020))
    del bad["reverse"]
    _write_bench(bench, json.dumps(bad), "step.crc.json")

    result = _run(flow, project, _confirm(bench, output="step.crc.json"))

    crc = result.block_results[2]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == (
        "config malformed"
        + _READ_SUFFIX.format(copy="step_1.crc.json", ref="step.crc.json")
    ), crc.summary
    assert _cause(crc) == (
        "crc config invalid: CRC config is structurally invalid: "
        "field 'reverse' is missing"
    )


def test_r_flow_ext_12_7_two_refs_read_order(tmp_path: Path) -> None:
    """Two in-place reads in one block: the document first, then the A2L —
    the suffixes appear in read order."""
    project = _project(tmp_path, {"base.s19": _S19_SRC, "doc.json": _symbol_doc()})
    bench = _bench(tmp_path)
    _write_bench(bench, _a2l_text(0x1000), "cal.a2l")
    flow = Flow(
        name="two_refs",
        blocks=[
            _ext_block(bench, str(bench / "step.log"), str(bench / "cal.a2l")),
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "step.changes.json")),
            PatchBlock("step.changes.json", a2l_ref="cal.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )
    # run 1: the document travels as the second step's output too — but the
    # PATCH document must exist under the project for the first run; write it
    # before run 1 and let the step's output replace it from run 2 on.
    (project / "step.changes.json").write_text(_doc("AA"), encoding="utf-8")
    first = _run(
        flow,
        project,
        {1: ExternalStepConfirmation(1, str(bench / "step.log"), str(bench / "cal.a2l")),
         3: ExternalStepConfirmation(3, str(bench / "step.log"), str(bench / "step.changes.json"))},
    )
    assert first.status == "ok", [b.summary for b in first.block_results]
    _write_bench(bench, _a2l_text(0x1002), "cal.a2l")
    (bench / "step.changes.json").write_text(_doc("BB"), encoding="utf-8")
    (bench / "step.log").write_text("tool ran OK\n", encoding="utf-8")

    second = _run(
        flow,
        project,
        {1: ExternalStepConfirmation(1, str(bench / "step.log"), str(bench / "cal.a2l")),
         3: ExternalStepConfirmation(3, str(bench / "step.log"), str(bench / "step.changes.json"))},
    )

    patch = second.block_results[3]
    assert patch.summary == (
        "applied 1 entry"
        + _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
        + _READ_SUFFIX.format(copy="cal_1.a2l", ref="cal.a2l")
    ), patch.summary


def test_r_flow_ext_12_8_no_suffix_without_in_place_read(tmp_path: Path) -> None:
    """A run with no in-place read has no suffix (holds on base; the
    `in_place_reads` attribute itself is the Inc-8 API)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    bench = _bench(tmp_path)
    _write_bench(bench, _doc("AA"))
    flow = _flow_x(bench)

    result = _run(flow, project, _confirm(bench))

    assert result.block_results[2].summary == "applied 1 entry"
    assert result.in_place_reads == []


def test_r_flow_ext_12_9_suffix_survives_the_raise_exit(tmp_path: Path, monkeypatch) -> None:
    """[N-4] The suffix is applied whatever path ends the block: when the
    document apply raises AFTER an in-place read, the error summary still
    carries the suffix."""
    project, bench, flow = _two_runs_flow_x(tmp_path)
    _write_bench(bench, _doc("BB"))

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(fes, "apply_change_document", _boom)
    result = _run(flow, project, _confirm(bench))
    patch = result.block_results[2]
    assert patch.status == BLOCK_STATUS_ERROR
    assert patch.summary == (
        "error"
        + _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
    ), patch.summary


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="junctions are the Windows case")
def test_r_flow_ext_12_10_suffix_before_the_refusal_token(tmp_path: Path, monkeypatch) -> None:
    """[N-2 option (c)] An in-place read followed by a junction-refused A2L
    keeps the refusal token LAST in the summary (the lane's ✗ detail keeps
    coding on it) while still naming the copy."""
    project, bench, _ = _two_runs_flow_x(tmp_path)
    (project / "cal.a2l").write_text(_a2l_text(0x1000), encoding="utf-8")
    flow = _flow_x(bench, patch_a2l_ref="cal.a2l")
    _write_bench(bench, _doc("BB"))
    from tests.b97_fixtures import make_junction

    make_junction(project / "jl", project)
    flow2 = Flow(
        name="flow_x",
        blocks=[
            SourceBlock("base.s19"),
            _ext_block(bench, str(bench / "step.log"), str(bench / "step.changes.json")),
            PatchBlock("step.changes.json", a2l_ref="jl/cal.a2l"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = _run(flow2, project, _confirm(bench))

    patch = result.block_results[2]
    assert patch.status == BLOCK_STATUS_ERROR
    assert patch.summary.endswith("unresolved"), patch.summary
    assert (
        _READ_SUFFIX.format(copy="step.changes_1.json", ref="step.changes.json")
        in patch.summary
    ), patch.summary
    escape_lines = [d for d in patch.diagnostics if d.startswith("[MANIFEST-PATH-ESCAPE]")]
    assert len(escape_lines) == 1, patch.diagnostics


# ---------------------------------------------------------------------------
# R-FLOW-EXT.13 — the chain-set Input provenance names the copy
# ---------------------------------------------------------------------------


def test_r_flow_ext_13_chain_set_provenance_names_the_copy(tmp_path: Path) -> None:
    image_a = emit_s19_from_mem_map({0x1000: 0x01}, [(0x1000, 0x1001)])
    image_b = emit_s19_from_mem_map({0x1000: 0x09}, [(0x1000, 0x1001)])
    project = _project(tmp_path, {})
    bench = _bench(tmp_path)
    _write_bench(bench, image_a, "fw.s19")
    flow = Flow(
        name="load_flow",
        blocks=[
            _ext_block(bench, str(bench / "step.log"), str(bench / "fw.s19")),
            SourceBlock("fw.s19"),
            WriteOutBlock("out.s19"),
        ],
    )
    chain = ChainSpec(name="lane1", template="lane1", flow=flow)
    ctx = FlowContext(project_dir=project, external_confirmations=_confirm(bench, index=0, output="fw.s19"))
    first = run_chain_set([chain], ctx, mode=CHAIN_RUN_SEQUENTIAL)
    assert first.outcomes[0].status == "ok"
    _write_bench(bench, image_b, "fw.s19")

    record = run_chain_set([chain], ctx, mode=CHAIN_RUN_SEQUENTIAL)

    outcome = record.outcomes[0]
    assert outcome.inputs == [("fw.s19", str(project / "fw_1.s19"))]
    text = record.report_path.read_text(encoding="utf-8")
    provenance = text.split("## Input provenance")[1].split("## Written files")[0]
    expected_line = (
        f"- Chain lane1 input 1: fw.s19 [bound] path=`{project / 'fw_1.s19'}`"
        + _READ_SUFFIX.format(copy="fw_1.s19", ref="fw.s19")
    )
    assert expected_line in provenance, provenance


def test_r_flow_ext_13_2_unbound_input_keeps_the_base_line(tmp_path: Path) -> None:
    """An unbound input keeps the base provenance line (holds on base; pinned
    so the suffix never leaks onto a plain input)."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    chain = ChainSpec(
        name="lane1",
        template="lane1",
        flow=Flow(
            name="lane1",
            blocks=[SourceBlock("base.s19"), WriteOutBlock("out.s19")],
        ),
    )
    record = run_chain_set(
        [chain], FlowContext(project_dir=project), mode=CHAIN_RUN_SEQUENTIAL
    )
    outcome = record.outcomes[0]
    assert outcome.inputs == [("base.s19", str(project / "base.s19"))]
    assert outcome.in_place_inputs == {}
    text = record.report_path.read_text(encoding="utf-8")
    provenance = text.split("## Input provenance")[1].split("## Written files")[0]
    expected_line = f"- Chain lane1 input 1: base.s19 [bound] path=`{project / 'base.s19'}`"
    assert expected_line in provenance, provenance
    assert "in place of" not in provenance


# ---------------------------------------------------------------------------
# R-FLOW-EXT.14 — a relative path that climbs above the project is refused
# ---------------------------------------------------------------------------


def test_r_flow_ext_14_climbing_path_refused_log(tmp_path: Path) -> None:
    """[S-3] A relative log that climbs above the project folder is refused
    before anything is copied."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    climbed = project.parent / "step.log"
    climbed.write_text("tool ran OK\n", encoding="utf-8")
    bench = _bench(tmp_path)
    (bench / "step.changes.json").write_text(_doc("AA"), encoding="utf-8")
    flow = _flow_x(bench, log="../step.log")

    result = _run(flow, project, _confirm(bench, log="../step.log"))

    ext = result.block_results[1]
    assert ext.status == BLOCK_STATUS_ERROR
    assert ext.summary == "external step refused", ext.summary
    assert _cause(ext) == (
        "log '../step.log' climbs above the project folder - "
        "give an absolute path for a file outside the project"
    )
    assert not list(project.glob("step.changes*.json"))


def test_r_flow_ext_14_climbing_path_refused_output(tmp_path: Path) -> None:
    """[S-3] A relative output that climbs above the project folder is
    refused; nothing is copied into the project."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "bench").mkdir()
    climbed = project.parent.parent / "x.json"
    climbed.write_text(_doc("AA"), encoding="utf-8")
    bench = _bench(tmp_path)
    (bench / "step.log").write_text("tool ran OK\n", encoding="utf-8")
    flow = _flow_x(bench, output="bench/../../x.json")

    result = _run(
        flow,
        project,
        {1: ExternalStepConfirmation(1, str(bench / "step.log"), "bench/../../x.json")},
    )

    ext = result.block_results[1]
    assert ext.status == BLOCK_STATUS_ERROR
    assert ext.summary == "external step refused", ext.summary
    assert _cause(ext) == (
        "output 'bench/../../x.json' climbs above the project folder - "
        "give an absolute path for a file outside the project"
    )
    assert not list(project.glob("*.json"))


def test_r_flow_ext_14_climbing_path_inside_accepted(tmp_path: Path) -> None:
    """A relative path that stays inside the project is accepted."""
    project = _project(tmp_path, {"base.s19": _S19_SRC})
    (project / "bench").mkdir()
    (project / "rel.changes.json").write_text(_doc("AA"), encoding="utf-8")
    bench = _bench(tmp_path)
    (bench / "step.log").write_text("tool ran OK\n", encoding="utf-8")
    flow = _flow_x(bench, output="bench/../rel.changes.json")

    result = _run(
        flow,
        project,
        {1: ExternalStepConfirmation(1, str(bench / "step.log"), "bench/../rel.changes.json")},
    )

    ext = result.block_results[1]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary == (
        "log 'step.log' received · output copied to rel.changes.json (session)"
    ), ext.summary


# ---------------------------------------------------------------------------
# R-FLOW-EXT.11 — the earlier copy keeps its bytes and its name
# ---------------------------------------------------------------------------


def test_r_flow_ext_11_earlier_copy_unchanged_bytes(tmp_path: Path) -> None:
    project, bench, flow = _two_runs_flow_x(tmp_path)
    first_bytes = (project / "step.changes.json").read_bytes()
    _write_bench(bench, _doc("BB"))

    _run(flow, project, _confirm(bench))

    assert (project / "step.changes.json").read_bytes() == first_bytes
    assert (project / "step.changes_1.json").read_bytes() == _doc("BB").encode("utf-8")


def test_r_flow_ext_11_earlier_copy_unchanged_names(tmp_path: Path) -> None:
    project, bench, flow = _two_runs_flow_x(tmp_path)
    _write_bench(bench, _doc("BB"))

    _run(flow, project, _confirm(bench))

    assert {path.name for path in project.iterdir()} == {
        "base.s19",
        "out.s19",
        "step.changes.json",
        "step.changes_1.json",
    }


# ---------------------------------------------------------------------------
# R-FLOW-CRC.3 / .4 / .9 — the Flow CRC block's summaries and causes
# ---------------------------------------------------------------------------


def test_r_flow_crc_3_missing_config_exact_text(tmp_path: Path) -> None:
    """A missing config file: summary `config unresolved`, the exact cause,
    later blocks skipped (holds on base — pinned exact-text)."""
    project = _project(tmp_path, {"prg.s19": _S19_SRC})
    flow = Flow(
        name="bad",
        blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc, write_out = result.block_results[1], result.block_results[2]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == "config unresolved", crc.summary
    assert _cause(crc) == "crc config not found or not inside the project"
    assert write_out.status == BLOCK_STATUS_SKIPPED
    assert result.status == "error"
    assert not result.written_paths


def test_r_flow_crc_4_designer_template_is_named_in_the_flow(tmp_path: Path) -> None:
    """[F-28] A file the CRC Designer saved: summary `config malformed`, the
    cause names the template; WRITE-OUT skipped, nothing written."""
    project = _project(
        tmp_path,
        {
            "firmware.s19": _S19_SRC,
            "templates/demo-crc32.crc.json": emit_template(seed_template()),
        },
    )
    flow = Flow(
        name="tpl",
        blocks=[
            SourceBlock("firmware.s19"),
            CrcBlock("templates/demo-crc32.crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc, write_out = result.block_results[1], result.block_results[2]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == "config malformed", crc.summary
    assert _cause(crc) == f"crc config invalid: CRC config is structurally invalid: {_TEMPLATE_REASON}"
    assert write_out.status == BLOCK_STATUS_SKIPPED
    assert result.status == "error"
    assert not result.written_paths
    assert not (project / "out.s19").exists()


def test_r_flow_crc_4_missing_field_is_named_in_the_flow(tmp_path: Path) -> None:
    """A config without `reverse`: the cause names the field."""
    config = json.loads(_crc_config_text(0x2000))
    del config["reverse"]
    project = _project(tmp_path, {"prg.s19": _S19_SRC, "crc.json": json.dumps(config)})
    flow = Flow(
        name="missing",
        blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc = result.block_results[1]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == "config malformed", crc.summary
    assert _cause(crc) == (
        "crc config invalid: CRC config is structurally invalid: "
        "field 'reverse' is missing"
    )


def test_r_flow_crc_4_not_json_cause(tmp_path: Path) -> None:
    """A config that is not JSON: the cause starts with the not-JSON prefix
    (holds on base — pinned exact-text)."""
    project = _project(tmp_path, {"prg.s19": _S19_SRC, "crc.json": "{ not valid json"})
    flow = Flow(
        name="notjson",
        blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc = result.block_results[1]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == "config malformed", crc.summary
    assert _cause(crc).startswith("crc config invalid: CRC config is not valid JSON: ")


def test_r_flow_crc_9_over_limit_config_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """[S-5] With the read cap lowered to 16 bytes, a 32-byte config is not
    read: the cause carries the size and the cap."""
    monkeypatch.setattr(crc_config_module, "READ_SIZE_CAP_BYTES", 16)
    project = _project(tmp_path, {"prg.s19": _S19_SRC, "crc.json": "x" * 32})
    flow = Flow(
        name="over",
        blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc, write_out = result.block_results[1], result.block_results[2]
    assert crc.status == BLOCK_STATUS_ERROR
    assert crc.summary == "config malformed", crc.summary
    assert _cause(crc) == (
        "crc config invalid: CRC config file is 32 bytes, over the "
        "16-byte read cap — the file was not read"
    )
    assert write_out.status == BLOCK_STATUS_SKIPPED
