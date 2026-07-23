"""batch-52 — Flow Builder CRC block (engine layer, Inc-1).

Black-box ATs drive the shipped ``run_flow`` engine surface directly and inspect
the ``FlowRunResult`` + the written artifact-on-disk. Every project is built
under a real ``.s19tool/workarea/`` root because WRITE-OUT emits there.

Traceability (01-requirements.md):
  AT-123 compute+inject · AT-124 grow / no-grow · AT-125 ordering WARN / no-warn
  AT-126 malformed fail-close · AT-127 containment triad
  TC-346 model · TC-347 over-post-patch · TC-355 no-raise · LLR-094.1 pre_crc_ranges

RED pre-state (recorded §5.1): before Inc-1, ``BLOCK_CRC`` / ``CrcBlock`` do not
exist, so every CRC flow fails at construction/import.
"""

from __future__ import annotations

import json
from pathlib import Path

from s19_app.core import S19File
from s19_app.tui.operations.crc import check_regions, encode_le
from s19_app.tui.operations.crc_config import parse_crc_config
from s19_app.tui.operations.model import OperationInput
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_CRC,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    WRITE_FMT_S19,
    CrcBlock,
    Flow,
    FlowBlock,
    FlowContext,
    FlowRunResult,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.load_service import build_loaded_s19

# Source image: one data record at 0x1000 = 01 02 03 04 -> ranges [(0x1000,0x1004)].
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


def _crc_config(output_address: str, start: str = "0x1000", end: str = "0x1004") -> str:
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


def _reload(path: Path) -> dict[int, int]:
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


def _reload_ranges(path: Path) -> list[tuple[int, int]]:
    return build_loaded_s19(path, S19File(str(path)), None, None).ranges


def _expected_crc(mem_map: dict[int, int], ranges, config_json: str):
    """Independent kernel oracle: (output_address, LE bytes) over ``mem_map``."""
    config, errors = parse_crc_config(config_json)
    assert config is not None and not errors, errors
    op = OperationInput(
        mem_map=dict(mem_map), ranges=list(ranges), input_path=None,
        variant_id=None, file_type="s19",
    )
    region = check_regions(op, config)[0]
    return region.output_address, encode_le(region.computed_crc, region.output_bytes)


# ---------------------------------------------------------------------------
# TC-346 — model
# ---------------------------------------------------------------------------

def test_tc346_crc_block_model() -> None:
    block = CrcBlock(config_ref="crc.json")
    assert block.kind == BLOCK_CRC == "crc"
    assert block.config_ref == "crc.json"
    assert CrcBlock in FlowBlock.__args__
    assert "pre_crc_ranges" in FlowRunResult.__dataclass_fields__


# ---------------------------------------------------------------------------
# AT-123 — compute + inject over the working image
# ---------------------------------------------------------------------------

def test_at123_crc_computed_and_injected_at_output_address(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x2000")
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="crc",
        blocks=[
            SourceBlock("prg.s19", file_type=WRITE_FMT_S19),
            PatchBlock("patch.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19", fmt=WRITE_FMT_S19),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    assert [br.status for br in result.block_results] == [
        BLOCK_STATUS_OK, BLOCK_STATUS_OK, BLOCK_STATUS_OK, BLOCK_STATUS_OK
    ]
    written_mem = _reload(result.written_paths[0])
    patched = {0x1000: 0xAA, 0x1001: 0x02, 0x1002: 0x03, 0x1003: 0x04}
    out_addr, expected = _expected_crc(patched, [(0x1000, 0x1004)], cfg)
    for i, byte in enumerate(expected):
        assert written_mem[out_addr + i] == byte, (
            f"CRC byte {i} at {hex(out_addr + i)}: "
            f"{written_mem.get(out_addr + i)} != {byte}"
        )


def test_tc347_crc_computed_over_post_patch_image(tmp_path: Path) -> None:
    """The CRC reflects the PATCHED bytes, not the source bytes — proving the
    block computed over the post-patch working image (LLR-089.2)."""
    cfg = _crc_config(output_address="0x2000")
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="crc",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("patch.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    written_mem = _reload(result.written_paths[0])

    # Oracle over the PATCHED image (0x1000 -> 0xAA) must match the written CRC…
    patched = {0x1000: 0xAA, 0x1001: 0x02, 0x1002: 0x03, 0x1003: 0x04}
    out_addr, expected_patched = _expected_crc(patched, [(0x1000, 0x1004)], cfg)
    for i, byte in enumerate(expected_patched):
        assert written_mem[out_addr + i] == byte
    # …and must DIFFER from the CRC over the un-patched source (discriminator).
    src = {0x1000: 0x01, 0x1001: 0x02, 0x1002: 0x03, 0x1003: 0x04}
    _, expected_source = _expected_crc(src, [(0x1000, 0x1004)], cfg)
    assert expected_patched != expected_source


# ---------------------------------------------------------------------------
# AT-124 — grow / no-grow (C-10 both branches)
# ---------------------------------------------------------------------------

def test_at124a_crc_grows_image_when_output_outside_ranges(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x2000")  # outside [0x1000,0x1004)
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="grow",
        blocks=[
            SourceBlock("prg.s19"), PatchBlock("patch.json"),
            CrcBlock("crc.json"), WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    # image_ranges include the new CRC window absent from the SOURCE footprint.
    assert (0x1000, 0x1004) not in [(0x2000, 0x2004)]  # sanity
    covered = _covers(result.image_ranges, 0x2000, 0x2004)
    assert covered, f"image_ranges {result.image_ranges} miss the CRC window"
    assert not _covers([(0x1000, 0x1004)], 0x2000, 0x2004)  # absent from source
    # …and the WRITTEN file's ranges include it too.
    assert _covers(_reload_ranges(result.written_paths[0]), 0x2000, 0x2004)
    # pre_crc_ranges (before) is strictly smaller than image_ranges (after).
    assert _span(result.pre_crc_ranges) < _span(result.image_ranges)


def test_at124b_crc_no_grow_when_output_inside_ranges(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x1000")  # inside [0x1000,0x1004)
    patch = _patch_doc([{"type": "bytes", "address": "0x1003", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="nogrow",
        blocks=[
            SourceBlock("prg.s19"), PatchBlock("patch.json"),
            CrcBlock("crc.json"), WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK
    assert result.image_ranges == [(0x1000, 0x1004)]  # unchanged footprint
    assert _span(result.pre_crc_ranges) == _span(result.image_ranges)  # before==after


# ---------------------------------------------------------------------------
# AT-125 — ordering guidance (WARN before PATCH / no warn after)
# ---------------------------------------------------------------------------

def test_at125a_crc_before_patch_warns_but_still_runs(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x2000")
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="misordered",
        blocks=[
            SourceBlock("prg.s19"),
            CrcBlock("crc.json"),      # index 1 — BEFORE the patch
            PatchBlock("patch.json"),  # index 2
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc = result.block_results[1]
    assert crc.status == BLOCK_STATUS_NOTICES
    assert any("CRC before PATCH" in f.message for f in crc.findings)
    assert result.status == FLOW_STATUS_ISSUES
    # Non-blocking: every block still executed, the file was still written.
    assert len(result.block_results) == len(flow.blocks)
    assert result.block_results[-1].status == BLOCK_STATUS_OK
    assert len(result.written_paths) == 1


def test_at125b_crc_after_patch_does_not_warn(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x2000")
    patch = _patch_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}])
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "patch.json": patch, "crc.json": cfg}
    )
    flow = Flow(
        name="ordered",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("patch.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    crc = result.block_results[2]
    assert crc.status == BLOCK_STATUS_OK
    assert crc.findings == []
    assert result.status == FLOW_STATUS_OK


def test_tc351_crc_only_flow_no_patch_warns(tmp_path: Path) -> None:
    cfg = _crc_config(output_address="0x2000")
    project = _make_project(tmp_path, {"prg.s19": _S19_SRC, "crc.json": cfg})
    flow = Flow(name="nopatch", blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json")])

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_NOTICES
    assert result.status == FLOW_STATUS_ISSUES


# ---------------------------------------------------------------------------
# AT-126 — malformed config fails closed
# ---------------------------------------------------------------------------

def test_at126_malformed_config_fails_closed(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path, {"prg.s19": _S19_SRC, "crc.json": "{ not valid json"}
    )
    flow = Flow(
        name="bad",
        blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json"), WriteOutBlock("out.s19")],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_ERROR
    assert result.block_results[2].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert len(result.block_results) == len(flow.blocks)  # never raised
    assert not result.written_paths  # image un-injected, nothing written


def test_tc346b_empty_config_file_fails_closed(tmp_path: Path) -> None:
    project = _make_project(tmp_path, {"prg.s19": _S19_SRC, "crc.json": ""})
    flow = Flow(name="empty", blocks=[SourceBlock("prg.s19"), CrcBlock("crc.json")])

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_ERROR
    assert result.status == FLOW_STATUS_ERROR


# ---------------------------------------------------------------------------
# AT-127 — containment triad (absolute / escape) — reused manifest guard
# ---------------------------------------------------------------------------

def test_at127a_absolute_config_ref_rejected(tmp_path: Path) -> None:
    """An ABSOLUTE config_ref pointing at a VALID config OUTSIDE the project is
    rejected by containment (proving containment, not mere existence)."""
    outside = tmp_path / "outside_crc.json"
    outside.write_text(_crc_config(output_address="0x2000"), encoding="utf-8")
    project = _make_project(tmp_path, {"prg.s19": _S19_SRC})
    flow = Flow(
        name="abs",
        blocks=[
            SourceBlock("prg.s19"),
            CrcBlock(str(outside.resolve())),  # absolute path
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_ERROR
    assert result.block_results[2].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert not result.written_paths


def test_at127b_escape_config_ref_rejected(tmp_path: Path) -> None:
    """A ``..``-escaping config_ref is rejected before any file open."""
    project = _make_project(tmp_path, {"prg.s19": _S19_SRC})
    outside = tmp_path / ".s19tool" / "workarea" / "escape_crc.json"
    outside.write_text(_crc_config(output_address="0x2000"), encoding="utf-8")
    flow = Flow(
        name="escape",
        blocks=[
            SourceBlock("prg.s19"),
            CrcBlock("../escape_crc.json"),  # escapes the project dir
            WriteOutBlock("out.s19"),
        ],
    )

    result = run_flow(flow, FlowContext(project_dir=project))

    assert result.block_results[1].status == BLOCK_STATUS_ERROR
    assert result.block_results[2].status == BLOCK_STATUS_SKIPPED
    assert result.status == FLOW_STATUS_ERROR
    assert not result.written_paths


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _covers(ranges, lo: int, hi: int) -> bool:
    """True when [lo,hi) is fully covered by the (start,end) ranges."""
    return any(start <= lo and hi <= end for start, end in ranges)


def _span(ranges) -> int:
    return sum(end - start for start, end in ranges)
