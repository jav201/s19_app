"""Batch-99 HLR-159 / LLR-155.8: a CRC never covers an empty region; the CRC write stages privately.

TC-B99-26 (LLR-159.1) — a flow CRC step whose region holds 0 image bytes ends
the block (and the flow) ``error``, injects nothing, and stops the flow before
any later WRITE-OUT: zero files are written and the image's slot bytes stay
absent.

TC-B99-27 (LLR-159.2, ARCH R23) — a flow CRC step over a partly covered legacy
region ends ``notices`` naming the exact count of absent bytes; the count is
asserted against an independent count of absent addresses computed from the
independent reader's map of ``prg.s19``, and the count is shown to travel on
the CRC region result.

TC-B99-38 (LLR-155.8) — two concurrent CRC writes of the same stem place each
file through the private staging (never a shared ``temp/<name>``): over 20
trials every written file's CRC slot is checked, with the independent reader
and ``zlib.crc32``, against the CRC of the image that wrote it.

AT-B99-10 (US-148) — black-box Textual pilot over Flow Execution (``#fx_run``):
a lane whose CRC step covers ``0x20000-0x30000`` of ``prg.s19`` paints the CRC
card failed, writes no file, and the run log names the cause (UX-C2); a lane
whose CRC step straddles a gap ends with notices, paints the exact absent
count on its terminal log line (HLR-159 / UX-C2), and still writes a file
whose CRC slot matches an independent CRC over the present bytes.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.operations.crc import CrcOperation, check_regions
from s19_app.tui.operations.crc_config import parse_crc_config
from s19_app.tui.operations.model import OperationInput
from s19_app.tui.services.flow_execution_service import (
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
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    CrcBlock,
    Flow,
    FlowContext,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.screens import LoadFlowScreen, LoadProjectScreen
from tests.b97_fixtures import write_flow
from tests.support.independent_reader import read_s19
from tests.support.b100_projects import dismiss_load_result_panel

ROOT = Path(__file__).resolve().parents[1]
PRG = ROOT / "examples" / "case_00_public" / "prg.s19"

#: A region of prg.s19 holding no image byte at all (LLR-159.1's case).
EMPTY_START, EMPTY_END, EMPTY_OUTPUT = 0x20000, 0x30000, 0x2FFFC
#: A legacy region straddling the 0xFA2E-0xFCB0 gap: 46 present bytes,
#: 466 absent ones (independently countable from the reader's map).
PARTIAL_START, PARTIAL_END, PARTIAL_OUTPUT = 0xFA00, 0xFC00, 0xFC00
#: The "exactly 1 present byte" boundary (LLR-159.1 vs LLR-159.2): only
#: 0xFA2D holds an image byte, so the absent count is the span length - 1.
BOUNDARY_START, BOUNDARY_END, BOUNDARY_OUTPUT = 0xFA2D, 0xFA31, 0xFC00


def _crc_config(start: str, end: str, output_address: str) -> str:
    return json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": True,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {"start": start, "end": end, "output_address": output_address}
            ],
        }
    )


def _change_doc(entries: list[dict]) -> str:
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


def _make_project(tmp_path: Path, name: str = "proj") -> Path:
    """``<tmp>/.s19tool/workarea/<name>/`` holding a copy of ``prg.s19``."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PRG, project_dir / "prg.s19")
    return project_dir


def _absent_count(oracle, start: int, end: int) -> int:
    """The independent count of absent addresses in ``[start, end)``."""
    return sum(1 for addr in range(start, end) if addr not in oracle.data)


def _covers(ranges, lo: int, hi: int) -> bool:
    """True when ``[lo, hi)`` is fully covered by the ``(start, end)`` ranges."""
    return any(start <= lo and hi <= end for start, end in ranges)


# --------------------------------------------------------------------------- #
# TC-B99-26 — LLR-159.1: an empty region is an error and injects nothing
# --------------------------------------------------------------------------- #


def test_tc_b99_26_empty_region_errors_and_writes_nothing(tmp_path: Path) -> None:
    """``0x20000-0x30000`` on ``prg.s19`` → the CRC block errors, the flow
    stops before WRITE-OUT (0 files), the slot bytes stay absent, and the
    block's last diagnostic names the cause (UX-C2). RED at HEAD (P-9):
    ``run=ok crc=ok … slot_bytes=00000000``."""
    project = _make_project(tmp_path)
    (project / "empty_crc.json").write_text(
        _crc_config("0x20000", "0x30000", "0x2FFFC"), encoding="utf-8"
    )
    flow = Flow(
        name="region_no_bytes",
        blocks=[
            SourceBlock("prg.s19"),
            CrcBlock("empty_crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK,
        BLOCK_STATUS_ERROR,
        BLOCK_STATUS_SKIPPED,
    ]
    assert result.status == FLOW_STATUS_ERROR
    # UX-C2: the last diagnostic of the error block is the user-facing cause.
    assert result.block_results[1].diagnostics[-1] == (
        "CRC region 0x20000-0x30000 holds 0 image bytes - nothing written"
    )
    # Nothing injected: the flow stops before WRITE-OUT and no file is written.
    assert not result.written_paths
    assert not (project / "out.s19").exists()
    # The image footprint never claims the slot window.
    assert not _covers(result.image_ranges, EMPTY_OUTPUT, EMPTY_OUTPUT + 4)


def test_tc_b99_26_empty_region_error_note_is_last_and_only() -> None:
    """F2 arm (LLR-159.1 / UX-C2, review finding F2): on the operation path
    a fully empty region gets the summary and the error cause ONLY — no
    "covers present bytes only" coverage note precedes the error (the cause
    stays the last line), and the coverage count is read from the region
    results, never re-derived (ARCH R23).

    RED at the pre-fix Inc-5 tree: the notes carried THREE entries — the
    summary, a "65536 absent byte(s) - the CRC covers present bytes only"
    coverage note, then the error."""
    oracle = read_s19(PRG)
    op_input = OperationInput(
        mem_map=dict(oracle.data),
        ranges=[(EMPTY_START, EMPTY_END)],
        input_path=None,
        variant_id=None,
        file_type="s19",
    )
    config, errors = parse_crc_config(
        _crc_config("0x20000", "0x30000", "0x2FFFC")
    )
    assert errors == []

    result = CrcOperation().execute(op_input, config=config)

    assert result.status == "error"
    assert len(result.notes) == 2, result.notes
    assert not any("present bytes only" in n for n in result.notes), (
        result.notes
    )
    # UX-C2: the cause stays the last line.
    assert result.notes[-1] == (
        "CRC region 0x20000-0x30000 holds 0 image bytes - nothing written"
    )


# --------------------------------------------------------------------------- #
# TC-B99-27 — LLR-159.2: partial coverage is a notice naming the absent count
# --------------------------------------------------------------------------- #


def test_tc_b99_27_partial_region_notices_name_absent_count(tmp_path: Path) -> None:
    """A legacy region over the 0xFA2E-0xFCB0 gap ends ``notices`` naming the
    exact count of absent bytes (== an independent count from the reader's
    map); the flow reports ``completed-with-issues`` and still writes a file
    whose slot matches an independent CRC over the present bytes.

    RED at HEAD (P-9): ``region_over_gap run=ok … findings=[]``."""
    project = _make_project(tmp_path)
    (project / "noop.json").write_text(_change_doc([]), encoding="utf-8")
    (project / "partial_crc.json").write_text(
        _crc_config("0xFA00", "0xFC00", "0xFC00"), encoding="utf-8"
    )
    flow = Flow(
        name="region_over_gap",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("noop.json"),  # keeps the CRC block AFTER a PATCH arm
            CrcBlock("partial_crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK,
        BLOCK_STATUS_OK,
        BLOCK_STATUS_NOTICES,
        BLOCK_STATUS_OK,
    ]
    assert result.status == FLOW_STATUS_ISSUES
    # The notice names the exact count of absent bytes.
    oracle = read_s19(project / "prg.s19")
    absent = _absent_count(oracle, PARTIAL_START, PARTIAL_END)
    assert absent == 466, "the fixture region must straddle the gap as pinned"
    declared = PARTIAL_END - PARTIAL_START
    notices = [
        f.message for f in result.block_results[2].findings
        if "region bytes absent" in f.message
    ]
    assert len(notices) == 1, result.block_results[2].findings
    # RE-PINNED (batch-99 Inc-5 review fix F1, LLR-159.2): the notice now
    # names the absent count against the declared span length
    # (old value: "466 absent byte(s)"; new value: "466 of 512 region bytes
    # absent (0xFA00-0xFC00)") — the finding text is the single carrier the
    # lane terminal line and the chain-set report paint.
    assert "0xFA00-0xFC00" in notices[0]
    assert f"{absent} of {declared} region bytes absent" in notices[0]
    # The injected CRC still covers the present bytes only.
    assert len(result.written_paths) == 1
    written = read_s19(result.written_paths[0])
    present = bytes(
        oracle.data[addr]
        for addr in range(PARTIAL_START, PARTIAL_END)
        if addr in oracle.data
    )
    slot = bytes(written.data[PARTIAL_OUTPUT + i] for i in range(4))
    assert slot == zlib.crc32(present).to_bytes(4, "little")


def test_tc_b99_27_r23_coverage_count_travels_on_the_region_result() -> None:
    """ARCH R23 (condition C5): the coverage count is carried on the CRC
    region result — every consumer reads that one number."""
    oracle = read_s19(PRG)
    op_input = OperationInput(
        mem_map=dict(oracle.data),
        ranges=[(PARTIAL_START, PARTIAL_END)],
        input_path=None,
        variant_id=None,
        file_type="s19",
    )

    empty_config, errors = parse_crc_config(
        _crc_config("0x20000", "0x30000", "0x2FFFC")
    )
    assert errors == []
    partial_config, errors = parse_crc_config(
        _crc_config("0xFA00", "0xFC00", "0xFC00")
    )
    assert errors == []

    empty_result = check_regions(op_input, empty_config)[0]
    # 0 present bytes: the absent count equals the declared span length.
    assert empty_result.absent_bytes == EMPTY_END - EMPTY_START
    partial_result = check_regions(op_input, partial_config)[0]
    assert partial_result.absent_bytes == _absent_count(
        oracle, PARTIAL_START, PARTIAL_END
    )
    # A fully covered region carries 0 — the boundary the flow arm reads.
    full_config, errors = parse_crc_config(
        _crc_config("0xEB08", "0xEB10", "0x2FFFC")
    )
    assert errors == []
    assert check_regions(op_input, full_config)[0].absent_bytes == 0


def test_tc_b99_27_boundary_one_present_byte_notices(tmp_path: Path) -> None:
    """F3 arm (LLR-159.1 vs LLR-159.2 boundary): a region holding EXACTLY
    ONE present byte is NOT the empty-region error — the block ends
    ``notices`` naming the absent count of span length − 1 (3 of 4), and the
    run still injects and writes a file whose slot matches an independent
    CRC over that single present byte.

    RED at the pre-fix Inc-5 tree: the notice read "3 absent byte(s)" (no
    declared-span form), so the count-form assertion fails."""
    project = _make_project(tmp_path)
    (project / "noop.json").write_text(_change_doc([]), encoding="utf-8")
    (project / "boundary_crc.json").write_text(
        _crc_config("0xFA2D", "0xFA31", "0xFC00"), encoding="utf-8"
    )
    flow = Flow(
        name="one_present_byte",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("noop.json"),  # keeps the CRC block AFTER a PATCH arm
            CrcBlock("boundary_crc.json"),
            WriteOutBlock("out_boundary.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK,
        BLOCK_STATUS_OK,
        BLOCK_STATUS_NOTICES,
        BLOCK_STATUS_OK,
    ]
    assert result.status == FLOW_STATUS_ISSUES
    oracle = read_s19(project / "prg.s19")
    absent = _absent_count(oracle, BOUNDARY_START, BOUNDARY_END)
    # The fixture region must hold exactly one present byte: the LLR-159.1
    # boundary — one byte fewer would be the error arm (TC-B99-26).
    assert absent == BOUNDARY_END - BOUNDARY_START - 1
    notices = [
        f.message for f in result.block_results[2].findings
        if "region bytes absent" in f.message
    ]
    assert len(notices) == 1, result.block_results[2].findings
    assert (
        f"{absent} of {BOUNDARY_END - BOUNDARY_START} region bytes absent "
        "(0xFA2D-0xFA31)" in notices[0]
    ), notices[0]
    # The injected CRC covers the single present byte and the run still
    # writes: the slot matches the independent oracle over that byte.
    assert len(result.written_paths) == 1
    written = read_s19(result.written_paths[0])
    present = bytes(
        oracle.data[addr]
        for addr in range(BOUNDARY_START, BOUNDARY_END)
        if addr in oracle.data
    )
    assert len(present) == 1
    slot = bytes(written.data[BOUNDARY_OUTPUT + i] for i in range(4))
    assert slot == zlib.crc32(present).to_bytes(4, "little")


def test_tc_b99_27_chain_set_report_lists_the_notice(tmp_path: Path) -> None:
    """F1 arm (HLR-159 / LLR-159.2 + LLR-020.2): the chain-set report lists
    the CRC block's finding text through ``md_safe`` — the always-present
    ``## Notices`` section names the lane, the block and the exact absent
    count; a clean lane lists ``none``.

    RED at the pre-fix Inc-5 tree: the report carried no ``## Notices``
    section and no finding text."""
    project = _make_project(tmp_path)
    (project / "noop.json").write_text(_change_doc([]), encoding="utf-8")
    (project / "partial_crc.json").write_text(
        _crc_config("0xFA00", "0xFC00", "0xFC00"), encoding="utf-8"
    )
    chains = [
        ChainSpec(
            name="gap_lane",
            template="gap_lane",
            flow=Flow(
                name="gap_lane",
                blocks=[
                    SourceBlock("prg.s19"),
                    PatchBlock("noop.json"),
                    CrcBlock("partial_crc.json"),
                    WriteOutBlock("out_gap.s19"),
                ],
            ),
            bindings={},
        )
    ]

    record = run_chain_set(chains, FlowContext(project_dir=project))
    text = compose_chain_set_report(
        record, "crc notices set", datetime(2026, 10, 25, tzinfo=timezone.utc)
    )

    assert "## Notices" in text, text
    assert "466 of 512 region bytes absent (0xFA00-0xFC00)" in text, text
    # The lane name is md_safe-escaped (``gap\_lane``); the block reference
    # and the finding text follow it.
    assert "block 3 (crc): CRC: 466 of 512" in text, text


# --------------------------------------------------------------------------- #
# TC-B99-38 — LLR-155.8: the CRC write stages privately
# --------------------------------------------------------------------------- #

#: The concurrent writers share one work area and one stem per trial; the
#: large payload keeps the shared-staging race window wide at HEAD (where both
#: writers stage at the same ``temp/<stem>`` path).
_TC38_REGION_START = 0x1000
_TC38_REGION_LEN = 0x80000  # 512 KiB, fully covered by each writer's image
_TC38_OUTPUT = 0x100000
_TC38_TRIALS = 20


def _tc38_payload(seed: int) -> bytes:
    return bytes((seed * 31 + i * 7 + 3) & 0xFF for i in range(_TC38_REGION_LEN))


def _tc38_op_input(payload: bytes) -> OperationInput:
    mem = {(_TC38_REGION_START + i): b for i, b in enumerate(payload)}
    return OperationInput(
        mem_map=mem,
        ranges=[(_TC38_REGION_START, _TC38_REGION_START + len(payload))],
        input_path=Path("fw.s19"),  # both writers derive the SAME stem
        variant_id=None,
        file_type="s19",
    )


def _tc38_write(workarea_base: Path, payload: bytes):
    config, errors = parse_crc_config(
        _crc_config(
            hex(_TC38_REGION_START),
            hex(_TC38_REGION_START + _TC38_REGION_LEN),
            hex(_TC38_OUTPUT),
        )
    )
    assert errors == []
    from s19_app.tui.operations.crc import write_crc_image

    return write_crc_image(
        _tc38_op_input(payload), config, workarea_base=workarea_base
    )


def _tc38_check_one(workarea_base: Path, payload: bytes) -> str:
    """One writer's half of a trial: returns "" when the file it wrote holds
    its own CRC slot, else a human-readable mismatch line."""
    result = _tc38_write(workarea_base, payload)
    if result.written_path is None:
        return f"no file written: {result.findings!r}"
    written = read_s19(result.written_path)
    slot = bytes(
        written.data[_TC38_OUTPUT + i] for i in range(4)
    )
    expected = zlib.crc32(payload).to_bytes(4, "little")
    if slot != expected:
        return (
            f"slot {slot.hex()} != own CRC {expected.hex()} "
            f"in {result.written_path.name}"
        )
    return ""


def test_tc_b99_38_concurrent_crc_writes_of_the_same_stem(tmp_path: Path) -> None:
    """Two concurrent writers of ``fw-crc.s19`` per trial, 20 trials: every
    written file's CRC slot equals its own image's CRC (independent reader +
    ``zlib.crc32`` oracle). Under shared ``temp/<name>`` staging (the HEAD
    behavior, restored by the LLR-155.8 mutation) the same probe reports a
    nonzero mismatch count (PQ-8)."""
    mismatches: list[str] = []
    for trial in range(_TC38_TRIALS):
        workarea_base = tmp_path / f"trial-{trial:02d}"
        payloads = [_tc38_payload(trial * 2), _tc38_payload(trial * 2 + 1)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            halves = list(
                pool.map(lambda p: _tc38_check_one(workarea_base, p), payloads)
            )
        mismatches.extend(h for h in halves if h)
    assert mismatches == [], (
        f"{len(mismatches)} of {_TC38_TRIALS * 2} concurrent writes landed "
        f"another image's bytes: {mismatches[:4]}"
    )


# --------------------------------------------------------------------------- #
# AT-B99-10 — US-148: black-box pilot over Flow Execution
# --------------------------------------------------------------------------- #


def _status_line(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


def _painted_log(app: S19TuiApp) -> str:
    """The painted Flow Execution run log (``#fx_log``, the AT-B99-03 idiom)."""
    from textual.widgets import Static

    return str(app.query_one("#fx_log", Static).render())


async def _wait_for(pilot, predicate, description: str, attempts: int = 200):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


async def _import_lane(app: S19TuiApp, pilot, stem: str, index: int) -> None:
    """Import ``flows/<stem>.json`` as a lane through the picker (clicks only)."""
    assert await pilot.click("#fx_import"), "click missed #fx_import"
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadFlowScreen)
        and any(
            item.name == stem
            for item in app.screen.query("#flow_list ListItem")
        ),
        f"the flow picker lists {stem}",
    )
    item = next(
        item for item in app.screen.query("#flow_list ListItem")
        if item.name == stem
    )
    await pilot.click(item)
    await pilot.pause()
    assert await pilot.click("#flow_load_ok"), "click missed #flow_load_ok"
    await _wait_for(
        pilot,
        lambda: len(app.query(f"#fx_lane_{index}")) > 0,
        f"the imported lane {index}",
    )


def test_at_b99_10_flow_crc_region_pilot(tmp_path: Path) -> None:
    """Flow Execution, driven ONLY by keys and clicks: the empty-region lane
    paints its CRC card ``✗ error``, writes no file and the run log names the
    cause (``CRC region 0x20000-0x30000 holds 0 image bytes - nothing
    written``); the gap-region lane paints ``◇ notices``, names the exact
    absent count on its terminal log line (``466 of 512 region bytes absent
    (0xFA00-0xFC00)``, HLR-159 / UX-C2 — Inc-5 review fix F1) and writes a
    file whose slot matches an independent CRC over the present bytes.

    RED at HEAD (P-9): both lanes run ``ok`` — the empty lane writes
    ``out_empty.s19`` and the log carries no cause line. RED at the pre-fix
    Inc-5 tree: the count text never reached the painted lane log line."""
    from textual.widgets import Label

    app = S19TuiApp(base_dir=tmp_path)
    project_dir = app.workarea / "proj1"
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PRG, project_dir / "prg.s19")
    (project_dir / "empty_crc.json").write_text(
        _crc_config("0x20000", "0x30000", "0x2FFFC"), encoding="utf-8"
    )
    (project_dir / "partial_crc.json").write_text(
        _crc_config("0xFA00", "0xFC00", "0xFC00"), encoding="utf-8"
    )
    (project_dir / "noop.json").write_text(_change_doc([]), encoding="utf-8")
    write_flow(
        project_dir,
        "empty_flow",
        [
            SourceBlock("prg.s19"),
            CrcBlock("empty_crc.json"),
            WriteOutBlock("out_empty.s19"),
        ],
    )
    write_flow(
        project_dir,
        "partial_flow",
        [
            SourceBlock("prg.s19"),
            PatchBlock("noop.json"),
            CrcBlock("partial_crc.json"),
            WriteOutBlock("out_partial.s19"),
        ],
    )

    async def _drive():
        async with app.run_test(size=(120, 54)) as pilot:
            await pilot.pause()
            # The project loads through the Load project dialog.
            await pilot.press("p")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LoadProjectScreen),
                "the Load project dialog",
            )
            row = next(
                row
                for row in app.screen.query("#project_list ListItem")
                if "proj1" in str(row.query_one(Label).render())
            )
            await pilot.click(row)
            await pilot.pause()
            assert await pilot.click("#project_ok"), "click missed #project_ok"
            # Inc 6 (HLR-178): the dialog route opens the Load-result panel;
            # dismiss it first with its shown key ``esc``.
            await dismiss_load_result_panel(pilot, app)
            await _wait_for(
                pilot,
                lambda: "proj1"
                in str(app.query_one("#status_context").render()),
                "the project context label",
            )
            await pilot.press("right_square_bracket")
            await _wait_for(
                pilot,
                lambda: len(app.query("#fx_panel")) > 0,
                "the Flow Execution panel",
            )
            await _import_lane(app, pilot, "empty_flow", 0)
            await _import_lane(app, pilot, "partial_flow", 1)
            assert await pilot.click("#fx_run"), "click missed #fx_run"
            await _wait_for(
                pilot,
                lambda: "chain halted" in _painted_log(app)
                and not app.query_one("#fx_run").disabled,
                "the failed lane painted in the run log",
            )

            log = _painted_log(app)
            # Empty region: the terminal line names the user-facing cause
            # (UX-C2) and the chain halts before WRITE-OUT.
            assert "empty_flow" in log, log
            assert "chain halted" in log, log
            assert (
                "CRC region 0x20000-0x30000 holds 0 image bytes - nothing written"
                in log
            ), log
            # Gap region: the lane ends with notices and still writes.
            assert "partial_flow" in log, log
            assert "done with notices" in log, log
            # F1 (HLR-159 / LLR-159.2, UX-C2): the painted terminal line
            # names the exact absent count against the declared span length.
            assert "466 of 512 region bytes absent (0xFA00-0xFC00)" in log, log
            # The painted lane cards carry the block statuses.
            panel = app.query_one("#fx_panel")
            assert "✗ error" in panel.lane_paint_plain(0), (
                panel.lane_paint_plain(0)
            )
            assert "◇ notices" in panel.lane_paint_plain(1), (
                panel.lane_paint_plain(1)
            )
            # The empty lane wrote nothing; the gap lane's slot matches an
            # independent CRC over the present bytes (the reader's oracle).
            assert not (project_dir / "out_empty.s19").exists(), (
                "WRITE-OUT ran despite the empty-region error"
            )
            out_partial = project_dir / "out_partial.s19"
            assert out_partial.exists(), "the notices lane wrote no file"
            oracle = read_s19(project_dir / "prg.s19")
            present = bytes(
                oracle.data[addr]
                for addr in range(PARTIAL_START, PARTIAL_END)
                if addr in oracle.data
            )
            written = read_s19(out_partial)
            slot = bytes(written.data[PARTIAL_OUTPUT + i] for i in range(4))
            assert slot == zlib.crc32(present).to_bytes(4, "little")

    asyncio.run(_drive())
