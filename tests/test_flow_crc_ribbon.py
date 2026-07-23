"""batch-52 — Flow Builder CRC block (twin ribbon + F3 + G-1, Inc-3).

AT-129 (e2e): the before/after memory ribbon shows a visibly LARGER after strip
  when a CRC block grew the image (more filled cells over the shared axis).
TC-360: a CRC that did NOT grow renders no separate before strip (single ribbon).
TC-361 (F3, LLR-094.3): the gating control is shown only for CHECK, hidden for
  every other kind (SOURCE default / CRC / …).
TC-358 (G-1): an empty flow renders without crashing.
LLR-094.1 (unit): the twin strips share an axis so growth = extra filled cells.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button, Select, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import (
    FlowBuilderPanel,
    _memory_ribbon_text,
)
from s19_app.tui.services.flow_model import (
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_SOURCE,
    CrcBlock,
    Flow,
    FlowRunResult,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)

from test_flow_builder_render import _run_in_panel
from test_flow_execution_service import _make_project

_S19_SRC = "S107100001020304DE\nS9030000FC\n"
_FILLED = "█"


def _crc_config(output_address: str) -> str:
    return json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": True,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {"start": "0x1000", "end": "0x1004", "output_address": output_address}
            ],
        }
    )


def _patch_doc(address: str) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [{"type": "bytes", "address": address, "bytes": "AA"}],
        }
    )


def _filled(widget) -> int:
    return widget.render().plain.count(_FILLED)


# ---------------------------------------------------------------------------
# LLR-094.1 (unit) — shared-axis twin: growth => extra filled cells
# ---------------------------------------------------------------------------

def test_llr0941_twin_shared_axis_growth_adds_filled_cells() -> None:
    before = [(0x1000, 0x1004)]
    after = [(0x1000, 0x1004), (0x2000, 0x2004)]
    axis = (0x1000, 0x2004)
    b = _memory_ribbon_text(before, window=axis).plain.count(_FILLED)
    a = _memory_ribbon_text(after, window=axis).plain.count(_FILLED)
    assert a > b
    # Without a shared axis each strip normalises to its own span (batch-51
    # behaviour, window=None) — unchanged.
    assert _memory_ribbon_text(before).plain  # non-empty, no crash


# ---------------------------------------------------------------------------
# AT-129 — twin ribbon shows growth through the shipped panel
# ---------------------------------------------------------------------------

def test_at129_twin_ribbon_after_larger_when_crc_grew(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_SRC,
            "patch.json": _patch_doc("0x1000"),
            "crc.json": _crc_config("0x2000"),  # grows the image
        },
    )
    blocks = [
        SourceBlock("prg.s19"),
        PatchBlock("patch.json"),
        CrcBlock("crc.json"),
        WriteOutBlock("out.s19"),
    ]

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _run_in_panel(app, pilot, project, blocks)
            before = app.query_one("#flow_result .flow-ribbon-before", Static)
            after = app.query_one("#flow_result .flow-ribbon", Static)
            return _filled(before), _filled(after)

    before_cells, after_cells = asyncio.run(_drive())
    assert after_cells > before_cells, (
        f"after ({after_cells}) must exceed before ({before_cells}) on growth"
    )


def test_tc360_no_before_strip_when_crc_did_not_grow(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path,
        {
            "prg.s19": _S19_SRC,
            "patch.json": _patch_doc("0x1003"),
            "crc.json": _crc_config("0x1000"),  # output IN range -> no growth
        },
    )
    blocks = [
        SourceBlock("prg.s19"),
        PatchBlock("patch.json"),
        CrcBlock("crc.json"),
        WriteOutBlock("out.s19"),
    ]

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _run_in_panel(app, pilot, project, blocks)
            return len(app.query("#flow_result .flow-ribbon-before"))

    assert asyncio.run(_drive()) == 0  # single ribbon, no before strip


# ---------------------------------------------------------------------------
# TC-361 (F3, LLR-094.3) — gating control CHECK-only
# ---------------------------------------------------------------------------

def test_tc361_gating_control_hidden_for_non_check(tmp_path: Path) -> None:
    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            kind = app.query_one("#flow_kind", Select)
            gating = app.query_one("#flow_gating", Select)
            out = {}
            kind.value = BLOCK_SOURCE
            await pilot.pause()
            out["source"] = gating.display
            kind.value = BLOCK_CRC
            await pilot.pause()
            out["crc"] = gating.display
            kind.value = BLOCK_CHECK
            await pilot.pause()
            out["check"] = gating.display
            return out

    vis = asyncio.run(_drive())
    assert vis["source"] is False
    assert vis["crc"] is False
    assert vis["check"] is True


# ---------------------------------------------------------------------------
# TC-358 (G-1) — empty flow renders without crashing
# ---------------------------------------------------------------------------

def test_tc358_empty_flow_renders_without_crash(tmp_path: Path) -> None:
    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            # empty flow list + an empty-result render must not raise
            panel.render_result(FlowRunResult(status="ok"))
            await pilot.pause()
            return panel.query_one("#flow_blocks", Static).render().plain

    blocks_text = asyncio.run(_drive())
    assert "no blocks yet" in blocks_text
