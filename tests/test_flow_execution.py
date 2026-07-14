"""Flow Builder run-engine tests (batch-44 tracer, R-TUI-059).

Projects are built under a real ``.s19tool/workarea/`` root because the
WRITE-OUT block stages through the work area (``save_patched_image``
containment) — the same setup ``test_variant_execution`` uses.
"""

from __future__ import annotations

import json
from pathlib import Path

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_OK,
    WRITE_FMT_HEX,
    WRITE_FMT_S19,
    Flow,
    FlowContext,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19

#: Minimal valid S19 — 4 bytes (01 02 03 04) at 0x1000 (checksum-verified).
_S19_A = "S107100001020304DE\nS9030000FC\n"


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_doc(entries: list[dict]) -> str:
    """A v2 ``s19app-changeset`` change document JSON string."""
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


def _reload_s19(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


def _reload_hex(path: Path) -> dict[int, int]:
    return build_loaded_hex(path, IntelHexFile(str(path)), None, None).mem_map


def test_run_flow_source_patch_writeout_happy_path(tmp_path: Path) -> None:
    """AC-1: SOURCE → PATCH → WRITE-OUT runs, writes the patched image, and
    reports every block ``ok``.

    RED pre-code: ``flow_model`` / ``flow_execution_service`` do not exist
    (import error).
    """
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            "patch.json": _patch_doc(
                [{"type": "bytes", "address": "0x1000", "bytes": "AA"}]
            ),
        },
    )
    flow = Flow(
        name="tracer",
        blocks=[
            SourceBlock("prg.s19", file_type=WRITE_FMT_S19),
            PatchBlock("patch.json"),
            WriteOutBlock("out.s19", fmt=WRITE_FMT_S19),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK,
        BLOCK_STATUS_OK,
        BLOCK_STATUS_OK,
    ]
    assert len(result.written_paths) == 1
    written = result.written_paths[0]
    assert written.exists()
    # The written image carries the patched byte (0x1000 -> 0xAA).
    assert _reload_s19(written)[0x1000] == 0xAA


def test_run_flow_missing_source_isolates_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """AC-2: a missing SOURCE fails its block, SKIPS the rest, writes no file,
    and never raises — ``len(block_results) == len(blocks)``.
    """
    project = _make_project(
        tmp_path,
        {"patch.json": _patch_doc(
            [{"type": "bytes", "address": "0x1000", "bytes": "AA"}]
        )},
    )
    flow = Flow(
        name="broken",
        blocks=[
            SourceBlock("missing.s19"),
            PatchBlock("patch.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_ERROR
    assert len(result.block_results) == 3
    assert result.block_results[0].status == BLOCK_STATUS_ERROR
    assert result.block_results[1].status == BLOCK_STATUS_SKIPPED
    assert result.block_results[2].status == BLOCK_STATUS_SKIPPED
    assert result.written_paths == []


def test_run_flow_path_escape_ref_is_blocked(tmp_path: Path) -> None:
    """AC-2 / security F1: a SOURCE ref that escapes the project directory is
    refused by the containment guard — no open outside the project.
    """
    _make_project(tmp_path, {})  # establishes the workarea root
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    # A secret file OUTSIDE the project directory.
    (tmp_path / "secret.s19").write_text(_S19_A, encoding="utf-8")

    for escaping in ("../../secret.s19", str((tmp_path / "secret.s19"))):
        flow = Flow(name="evil", blocks=[SourceBlock(escaping)])
        result = run_flow(flow, FlowContext(project_dir=project))
        assert result.status == FLOW_STATUS_ERROR
        assert result.block_results[0].status == BLOCK_STATUS_ERROR
        joined = " ".join(result.block_results[0].diagnostics)
        assert "ESCAPE" in joined.upper() or "absolute" in joined, (
            f"expected a containment diagnostic; got {joined!r}"
        )


def test_run_flow_writeout_hex_and_s19_formats(tmp_path: Path) -> None:
    """AC-3: WRITE-OUT ``fmt="hex"`` emits Intel HEX and ``fmt="s19"`` emits
    S19; both carry the patched byte and round-trip through their parser.
    """
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_A,
            "patch.json": _patch_doc(
                [{"type": "bytes", "address": "0x1000", "bytes": "BE"}]
            ),
        },
    )
    base = [SourceBlock("prg.s19"), PatchBlock("patch.json")]

    hex_res = run_flow(
        Flow("h", blocks=base + [WriteOutBlock("out.hex", fmt=WRITE_FMT_HEX)]),
        FlowContext(project_dir=project),
    )
    assert hex_res.status == FLOW_STATUS_OK
    hex_path = hex_res.written_paths[0]
    assert hex_path.suffix == ".hex"
    assert _reload_hex(hex_path)[0x1000] == 0xBE

    s19_res = run_flow(
        Flow("s", blocks=base + [WriteOutBlock("out2.s19", fmt=WRITE_FMT_S19)]),
        FlowContext(project_dir=project),
    )
    assert s19_res.status == FLOW_STATUS_OK
    s19_path = s19_res.written_paths[0]
    assert s19_path.suffix == ".s19"
    assert _reload_s19(s19_path)[0x1000] == 0xBE
