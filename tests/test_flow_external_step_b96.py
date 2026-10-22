"""Batch-96 — the external-step block (spec "paso externo") ported to the real tree.

TC-1804 (white-box service arms + black-box shipped-surface arms): the
human-gated block carries, in BOTH modes, the instruction/command, a
MANDATORY log ref and an output file (absolute path preferred); persistence
is strict (unknown keys / empty instruction / empty log / shaped output all
refuse the block); execution WITHOUT a confirmation PAUSES the run
("paused - waiting for a human") and skips every downstream block, WITH one it validates
the log + output evidence, COPIES the output into the session artifact
folder (``copy_into_workarea`` — the copied path rides ``written_paths``)
and the chain goes on; the builder exposes the kind on the palette + the
kind select, gates its config row, and the fx lane mounts the confirm
button that re-runs the paused lane.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.flow_screens import FlowBuilderPanel
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_execution_service import ChainSpec, run_chain_set
from s19_app.tui.services.flow_model import (
    BLOCK_A2B,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    BLOCK_STATUS_WAITING,
    EXTERNAL_MODE_MANUAL,
    EXTERNAL_MODE_TERMINAL,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    FLOW_STATUS_PAUSED,
    ExternalStepBlock,
    ExternalStepConfirmation,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.workspace import copy_into_workarea

#: Minimal CLEAN S19 — 01 02 03 04 at 0x1000 (checksum-verified).
_S19 = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _external_payload(blocks: list) -> str:
    """A schema-v1 envelope around the given block dicts (wire text)."""
    return json.dumps({"schema_version": 1, "name": "ext", "blocks": blocks})


def _ext_chain(name: str, block: ExternalStepBlock) -> ChainSpec:
    return ChainSpec(
        name=name,
        template="base",
        flow=Flow(
            name=name,
            blocks=[SourceBlock("base.s19"), block, WriteOutBlock("out.s19")],
        ),
    )


def _ext_block(tmp_path: Path, **overrides) -> ExternalStepBlock:
    """A TERMINAL block whose log + output live OUTSIDE the project."""
    ext_dir = tmp_path / "externo"
    ext_dir.mkdir(exist_ok=True)
    base = {
        "mode": EXTERNAL_MODE_TERMINAL,
        "instruction": "python herramienta.py --release",
        "log_ref": str(ext_dir / "run.log"),
        "output_path": str(ext_dir / "salida.s19"),
    }
    base.update(overrides)
    return ExternalStepBlock(**base)


# --------------------------------------------------------------------------- #
# TC-1804 (a) — persistence: round-trip + strict grammar
# --------------------------------------------------------------------------- #


def test_tc1804_persistence_roundtrip_field_by_field(tmp_path: Path) -> None:
    """TC-1804 (persistence): a saved external-step block round-trips through
    the real parser field-by-field, in BOTH modes, and the serializer's wire
    projection carries EXACTLY the five strict keys (kind/mode/instruction/
    log_ref/output_path)."""
    project = _make_project(tmp_path, {"base.s19": _S19})
    blocks = [
        SourceBlock("base.s19"),
        _ext_block(tmp_path),
        ExternalStepBlock(
            mode=EXTERNAL_MODE_MANUAL,
            instruction="revisar el binario en el equipo de pruebas",
            log_ref="constancia.txt",
            output_path="salida_manual.s19",
        ),
    ]
    flow = Flow(name="ext_flow", blocks=blocks)
    path = fps.save_flow_json(flow, "ext_flow", project)
    assert path is not None
    wire = json.loads(path.read_text(encoding="utf-8"))
    ext_entries = [b for b in wire["blocks"] if b["kind"] == BLOCK_EXTERNAL_STEP]
    assert [sorted(e) for e in ext_entries] == [
        sorted(["kind", "mode", "instruction", "log_ref", "output_path"])
    ] * 2
    # The ABSOLUTE-path preference rides the wire verbatim (no resolution).
    assert ext_entries[0]["output_path"] == blocks[1].output_path

    loaded, findings = fps.load_flow_json(path, project)
    assert findings == []
    assert loaded is not None
    assert len(loaded.blocks) == 3
    for original, parsed in zip(blocks[1:], loaded.blocks[1:]):
        assert isinstance(parsed, ExternalStepBlock)
        assert parsed.mode == original.mode
        assert parsed.instruction == original.instruction
        assert parsed.log_ref == original.log_ref
        assert parsed.output_path == original.output_path


def test_tc1804_parser_refuses_missing_mandatory_fields(tmp_path: Path) -> None:
    """TC-1804 (persistence, strictness): an empty ``log_ref`` refuses the
    block (the log is MANDATORY evidence, never optional) with FLOW-BAD-FIELD;
    so does an empty ``instruction`` and an unknown extra key; a bad mode
    value is refused too — every refusal drops exactly that block."""
    project = _make_project(tmp_path, {})
    flows_dir = project / "flows"
    flows_dir.mkdir(exist_ok=True)
    refused_cases = {
        "empty_log": {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "terminal",
            "instruction": "run it",
            "log_ref": "  ",
            "output_path": str(tmp_path / "o.s19"),
        },
        "empty_instruction": {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "manual",
            "instruction": "",
            "log_ref": "log.txt",
            "output_path": str(tmp_path / "o.s19"),
        },
        "unknown_key": {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "terminal",
            "instruction": "run it",
            "log_ref": "log.txt",
            "output_path": str(tmp_path / "o.s19"),
            "extra": True,
        },
        "bad_mode": {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "telepathic",
            "instruction": "run it",
            "log_ref": "log.txt",
            "output_path": str(tmp_path / "o.s19"),
        },
        "empty_output": {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "terminal",
            "instruction": "run it",
            "log_ref": "log.txt",
            "output_path": "",
        },
    }
    for case, entry in refused_cases.items():
        flow_path = flows_dir / f"{case}.json"
        flow_path.write_text(_external_payload([entry]), encoding="utf-8")
        loaded, findings = fps.load_flow_json(flow_path, project)
        assert loaded is None or all(
            not isinstance(b, ExternalStepBlock) for b in loaded.blocks
        ), f"{case}: the refused block must not load"
        assert findings, f"{case}: a refusal finding is mandatory"


def test_tc1804_parser_output_path_shape(tmp_path: Path) -> None:
    """TC-1804 (persistence, output shape): an ABSOLUTE output path is
    preferred and rides verbatim; a plain relative filename is accepted (it
    resolves against the operator's CWD at confirm time); a relative path
    with separators, a traversal, a drive-relative or a hidden dot-name is
    refused with FLOW-UNSAFE-OUTPUT-NAME."""
    project = _make_project(tmp_path, {})
    flows_dir = project / "flows"
    flows_dir.mkdir(exist_ok=True)
    absolute = str(tmp_path / "fuera" / "salida.s19")
    accepted = {
        "absolute": absolute,
        "plain_relative": "salida.s19",
    }
    for case, output_path in accepted.items():
        entry = {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "terminal",
            "instruction": "run it",
            "log_ref": "log.txt",
            "output_path": output_path,
        }
        flow_path = flows_dir / f"ok_{case}.json"
        flow_path.write_text(_external_payload([entry]), encoding="utf-8")
        loaded, findings = fps.load_flow_json(flow_path, project)
        assert findings == [], f"{case}: {findings}"
        assert loaded is not None
        assert loaded.blocks[0].output_path == output_path

    refused = {
        "traversal": "..\\fuera\\salida.s19",
        "separators": "sub/dir/salida.s19",
        "drive_relative": "C:salida.s19",
        "hidden": ".salida.s19",
    }
    for case, output_path in refused.items():
        entry = {
            "kind": BLOCK_EXTERNAL_STEP,
            "mode": "terminal",
            "instruction": "run it",
            "log_ref": "log.txt",
            "output_path": output_path,
        }
        flow_path = flows_dir / f"bad_{case}.json"
        flow_path.write_text(_external_payload([entry]), encoding="utf-8")
        loaded, findings = fps.load_flow_json(flow_path, project)
        assert loaded is None or all(
            not isinstance(b, ExternalStepBlock) for b in loaded.blocks
        ), f"{case}: the shaped output must not load"
        assert any(
            "FLOW-UNSAFE-OUTPUT-NAME" in finding.code for finding in findings
        ), f"{case}: the shape finding names FLOW-UNSAFE-OUTPUT-NAME"


# --------------------------------------------------------------------------- #
# TC-1804 (b) — execution: pause / confirm / copy-into-session
# --------------------------------------------------------------------------- #


def test_tc1804_unconfirmed_run_pauses_and_skips_downstream(tmp_path: Path) -> None:
    """TC-1804 (execution, the pause): a run with NO confirmation PAUSES at
    the external step — the block result is ``waiting`` naming the pending
    LOG + OUTPUT ("waiting for a human"), the flow status is ``paused`` (NOT
    ``error`` — the image is intact), and the downstream WRITE-OUT skips
    with the waiting reason and writes nothing."""
    project = _make_project(tmp_path, {"base.s19": _S19})
    ctx = FlowContext(project_dir=project)
    record = run_chain_set(
        [_ext_chain("ext", _ext_block(tmp_path))], ctx, set_name="ext_set"
    )
    outcome = record.outcomes[0]
    assert outcome.status == FLOW_STATUS_PAUSED
    ext_result, write_result = outcome.block_results[1], outcome.block_results[2]
    assert ext_result.status == BLOCK_STATUS_WAITING
    # batch-97 Inc-2 (LLR-147.5): the service strings are English.
    assert "waiting for a human" in ext_result.summary
    assert ext_result.summary.count("pending") == 1
    assert write_result.status == BLOCK_STATUS_SKIPPED
    assert "waiting on external step" in write_result.summary
    # The image is intact: the SOURCE block ran clean…
    assert outcome.block_results[0].status == BLOCK_STATUS_OK
    # …and nothing downstream was written.
    assert not (project / "out.s19").exists()
    assert outcome.written_paths == []


def test_tc1804_confirmed_run_copies_output_into_session(tmp_path: Path) -> None:
    """TC-1804 (execution, the confirm): with the operator's confirmation the
    executor validates the MANDATORY log + the output file, COPIES the output
    INTO the session artifact folder (the run work area — the same
    ``copy_into_workarea`` idiom the imports use), records the copied path in
    ``written_paths`` and the chain CONTINUES (WRITE-OUT produces out.s19).
    The threaded image passes through unchanged."""
    project = _make_project(tmp_path, {"base.s19": _S19})
    block = _ext_block(tmp_path)
    ext_dir = Path(block.output_path).parent
    (ext_dir / "run.log").write_text("flashed OK\n", encoding="utf-8")
    (ext_dir / "salida.s19").write_text(_S19, encoding="utf-8")

    confirmation = ExternalStepConfirmation(
        block_index=1,
        log_ref=block.log_ref,
        source_path=block.output_path,
    )
    ctx = FlowContext(project_dir=project, external_confirmations={1: confirmation})
    record = run_chain_set(
        [_ext_chain("ext", block)], ctx, set_name="ext_set"
    )
    outcome = record.outcomes[0]
    assert outcome.status == FLOW_STATUS_OK
    ext_result = outcome.block_results[1]
    assert ext_result.status == BLOCK_STATUS_OK
    assert "output copied" in ext_result.summary
    # The copied file lives in the session artifact folder, byte-faithful to
    # the source the human produced (write_text may newline-translate — the
    # pin is source-vs-copy, not a literal).
    copied = project / "salida.s19"
    assert copied.is_file()
    assert copied.read_bytes() == (ext_dir / "salida.s19").read_bytes()
    # The copied path rides written_paths (the WRITE-OUT output too).
    assert copied in outcome.written_paths
    assert project / "out.s19" in outcome.written_paths
    assert (project / "out.s19").is_file()
    # The independent-oracle arm: the workarea helper agrees on the target.
    oracle = copy_into_workarea(Path(block.output_path), project)
    assert oracle == copied


def test_tc1804_confirmed_run_refuses_missing_evidence(tmp_path: Path) -> None:
    """TC-1804 (execution, the refusal): a confirmation whose MANDATORY log
    does not exist refuses the step (``error`` — the named mandatory-evidence
    message), as does a confirmation whose output file was never produced;
    the downstream WRITE-OUT stays skipped."""
    project = _make_project(tmp_path, {"base.s19": _S19})
    block = _ext_block(tmp_path)

    missing_log = ExternalStepConfirmation(
        block_index=1, log_ref=block.log_ref, source_path=block.output_path
    )
    ctx = FlowContext(project_dir=project, external_confirmations={1: missing_log})
    record = run_chain_set([_ext_chain("ext", block)], ctx, set_name="s")
    outcome = record.outcomes[0]
    assert outcome.status == FLOW_STATUS_ERROR
    assert any(
        "mandatory evidence" in line for line in outcome.block_results[1].diagnostics
    )

    ext_dir = Path(block.output_path).parent
    (ext_dir / "run.log").write_text("flashed OK\n", encoding="utf-8")
    missing_out = ExternalStepConfirmation(
        block_index=1, log_ref=block.log_ref, source_path=block.output_path
    )
    ctx2 = FlowContext(project_dir=project, external_confirmations={1: missing_out})
    record2 = run_chain_set([_ext_chain("ext", block)], ctx2, set_name="s")
    outcome2 = record2.outcomes[0]
    assert outcome2.status == FLOW_STATUS_ERROR
    assert any(
        "run the external step" in line
        for line in outcome2.block_results[1].diagnostics
    )
    assert outcome2.block_results[2].status == BLOCK_STATUS_SKIPPED
    assert not (project / "salida.s19").exists()


# --------------------------------------------------------------------------- #
# TC-1804 (c) — the shipped builder surface (black-box through the app)
# --------------------------------------------------------------------------- #


def test_tc1804_builder_palette_select_and_config_row_gate(tmp_path: Path) -> None:
    """TC-1804 (builder): the external-step kind rides the palette rail AND
    the kind select; choosing it hides the plain ref input and shows the
    config row; the Add button REFUSES a block without the MANDATORY log
    (visible wiring notice, block never added) and accepts a complete one —
    the canvas then paints the wider EXT-STEP box with its mode tag."""
    project = _make_project(tmp_path, {"base.s19": _S19})

    async def _drive() -> "tuple[list[str], list[str], str, int, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            palette_kinds = [
                button.id.removeprefix("flow_palette_")
                for button in app.query("#flow_palette Button")
            ]
            kind_values = [
                value for _label, value in FlowBuilderPanel._KIND_OPTIONS
            ]

            from textual.widgets import Button, Input, Select, Static

            app.query_one("#flow_kind", Select).value = BLOCK_EXTERNAL_STEP
            await pilot.pause()
            ext_row_visible = app.query_one("#flow_ext_row").display
            ref_hidden = not app.query_one("#flow_ref", Input).display
            session_text = app.query_one("#flow_ext_session", Static).render().plain

            # Refused: the MANDATORY log is empty.
            app.query_one("#flow_ext_instruction", Input).value = "make flash"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            notice_log = app.query_one("#flow_wiring_notice", Static).render().plain
            refused_count = len(panel._blocks)

            # Accepted: instruction + LOG + output path.
            app.query_one("#flow_ext_log", Input).value = "constancia.txt"
            app.query_one("#flow_ext_output", Input).value = str(
                tmp_path / "fuera" / "salida.s19"
            )
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            accepted_count = len(panel._blocks)
            canvas = app.query_one("#flow_canvas", Static).render().plain
            return (
                palette_kinds,
                kind_values,
                notice_log,
                refused_count * 10 + accepted_count,
                canvas + "|" + ("1" if ext_row_visible and ref_hidden else "0")
                + "|" + session_text,
            )

    palette_kinds, kind_values, notice, counts, canvas_pack = asyncio.run(_drive())
    session_text = canvas_pack.rsplit("|", 1)[1]
    canvas, gates = canvas_pack.rsplit("|", 2)[0], canvas_pack.rsplit("|", 2)[1]

    # batch-97 Inc-5 (named supersession): the palette offers every kind of
    # ``_KIND_OPTIONS`` (LLR-146.2); the refusal is English (LLR-146.7); the
    # session path rides the ribbon and ``#flow_ext_session`` stays mounted,
    # hidden, in English (LLR-146.11).
    assert palette_kinds == kind_values
    assert BLOCK_EXTERNAL_STEP in kind_values
    assert "log file is required" in notice and "refused" in notice
    assert counts == 1  # 0 kept after the refusal, 1 after the accept
    assert gates == "1"  # config row shown, plain ref hidden
    assert session_text.startswith("session: ")
    assert "EXT-STEP" in canvas and "TERMINAL" in canvas


def test_tc1804_fx_lane_pause_confirm_rerun(tmp_path: Path) -> None:
    """TC-1804 (fx surface): running a lane whose flow carries an unconfirmed
    external step PAUSES the lane — the painted lane names the pending LOG
    and "ESPERANDO HUMANO", the run log carries the □ pause line, and the
    lane's confirm button mounts; pressing it re-runs THAT lane, the
    executor validates the evidence, copies the output into the session
    artifact folder and the chain continues (out.s19 + the copied file)."""
    project = _make_project(tmp_path, {"base.s19": _S19})
    # A SHORT relative log ref: the painted pending row is tail-clipped at
    # the lane width, so the evidence text must fit "⚠ LOG '…' pendiente".
    block = _ext_block(tmp_path, log_ref="run.log")
    fps.save_flow_json(
        Flow(
            name="ext",
            blocks=[SourceBlock("base.s19"), block, WriteOutBlock("out.s19")],
        ),
        "ext",
        project,
    )

    async def _drive() -> "tuple[str, str, bool, str, bool]":
        from textual.widgets import Button, Static

        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            app.action_show_screen("flow_execution")
            await pilot.pause()
            # Import the saved flow through the real picker.
            app.query_one("#fx_import", Button).press()
            for _ in range(50):
                await pilot.pause()
                try:
                    app.screen.query_one("#flow_load_ok", Button)
                    break
                except Exception:
                    continue
            items = app.screen.query_one("#flow_list")
            for i, item in enumerate(items.query("ListItem")):
                if item.name == "ext":
                    items.index = i
                    break
            app.screen.query_one("#flow_load_ok", Button).press()
            await pilot.pause()
            await pilot.pause()

            app.query_one("#fx_run", Button).press()
            for _ in range(40):
                await pilot.pause()
            lane_paint = app.query_one("#fx_lane_0_paint", Static).render().plain
            log_text = app.query_one("#fx_log", Static).render().plain
            confirm_visible = app.query_one("#fx_confirm_0", Button).display

            # The human ran the step OUTSIDE the app: evidence now exists.
            # The relative log ref resolves against the session project dir.
            ext_dir = Path(block.output_path).parent
            (project / "run.log").write_text("flashed OK\n", encoding="utf-8")
            (ext_dir / "salida.s19").write_text(_S19, encoding="utf-8")
            app.query_one("#fx_confirm_0", Button).press()
            for _ in range(40):
                await pilot.pause()
            rerun_paint = app.query_one("#fx_lane_0_paint", Static).render().plain
            rerun_log = app.query_one("#fx_log", Static).render().plain
            confirm_hidden = not app.query_one("#fx_confirm_0", Button).display
            return (
                lane_paint,
                log_text,
                confirm_visible,
                rerun_paint + "\n" + rerun_log,
                confirm_hidden,
            )

    lane_paint, log_text, confirm_visible, rerun_text, confirm_hidden = asyncio.run(
        _drive()
    )

    # The pause paints: pending LOG row + the human-wait state word.
    assert "ESPERANDO HUMANO" in lane_paint
    assert "LOG" in lane_paint and "pendiente" in lane_paint
    assert "esperando humano" in log_text.lower() or "ESPERANDO HUMANO" in log_text
    assert confirm_visible is True
    # The confirm re-run: the lane is CLEAN again, the button hides, and the
    # log records the re-run + the written outputs.
    assert "✓" in rerun_text
    assert "re-run tras confirmar" in rerun_text
    assert confirm_hidden is True
    assert (project / "salida.s19").is_file()
    assert (project / "out.s19").is_file()
