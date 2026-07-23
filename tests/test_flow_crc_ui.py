"""batch-52 — Flow Builder CRC block (UI layer, Inc-2).

TC-356 (unit): CRC is an add-block dropdown option + builds/labels correctly.
AT-128 (e2e): a CRC block composed into the panel renders a CRC node and, after
the real Run, shows its post-run status through the shipped ``FlowBuilderPanel``.

Reuses the proven Pilot driver from ``test_flow_builder_render`` and the project
fixture helpers from ``test_flow_execution_service``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import (
    FlowBuilderPanel,
    _flow_block_label,
    _make_flow_block,
)
from s19_app.tui.services.flow_model import (
    BLOCK_CRC,
    CrcBlock,
    Flow,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)

from textual.widgets import Button, Static

from test_flow_builder_render import _nodes, _run_in_panel
from test_flow_execution_service import _make_project

_S19_SRC = "S107100001020304DE\nS9030000FC\n"


def _crc_config() -> str:
    return json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": True,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {"start": "0x1000", "end": "0x1004", "output_address": "0x2000"}
            ],
        }
    )


def _patch_doc() -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [{"type": "bytes", "address": "0x1000", "bytes": "AA"}],
        }
    )


def _node_text(widget) -> str:
    try:
        return widget.render().plain
    except Exception:  # noqa: BLE001 - non-text renderable
        return str(getattr(widget, "renderable", widget))


# ---------------------------------------------------------------------------
# TC-356 — CRC in the dropdown + build + label (unit)
# ---------------------------------------------------------------------------

def test_tc356_crc_in_dropdown_and_builder() -> None:
    values = [value for _label, value in FlowBuilderPanel._KIND_OPTIONS]
    assert BLOCK_CRC in values
    labels = [label for label, _value in FlowBuilderPanel._KIND_OPTIONS]
    assert any("CRC" in label for label in labels)
    # distinct label from CHECK / WRITE-OUT
    crc_label = next(l for l, v in FlowBuilderPanel._KIND_OPTIONS if v == BLOCK_CRC)
    assert crc_label not in {
        l for l, v in FlowBuilderPanel._KIND_OPTIONS if v != BLOCK_CRC
    }
    block = _make_flow_block(BLOCK_CRC, "crc.json")
    assert isinstance(block, CrcBlock)
    assert block.config_ref == "crc.json"
    assert _flow_block_label(block) == "CRC  crc.json"
    # empty ref no-ops (panel contract)
    assert _make_flow_block(BLOCK_CRC, "   ") is None


# ---------------------------------------------------------------------------
# AT-128 — CRC node renders + post-run status through the shipped panel
# ---------------------------------------------------------------------------

def test_at128_crc_node_renders_and_shows_status(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path,
        {"prg.s19": _S19_SRC, "patch.json": _patch_doc(), "crc.json": _crc_config()},
    )
    blocks = [
        SourceBlock("prg.s19"),
        PatchBlock("patch.json"),
        CrcBlock("crc.json"),
        WriteOutBlock("out.s19"),
    ]

    async def _drive() -> tuple[int, list[str], list[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            # pre-run block list carries the CRC label + config_ref (LLR-093.2)
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            panel._blocks = list(blocks)
            panel.query_one("#flow_blocks", Static).update(panel._blocks_text())
            await pilot.pause()
            blocks_list = _node_text(app.query_one("#flow_blocks", Static))
            # run and read the result nodes
            app.query_one("#flow_run", Button).press()
            await pilot.pause()
            await pilot.pause()
            node_count = len(_nodes(app))
            heads = [_node_text(s) for s in app.query("#flow_result .flow-node-head")]
            summaries = [
                _node_text(s) for s in app.query("#flow_result .flow-node-summary")
            ]
            return node_count, heads, summaries, blocks_list

    node_count, heads, summaries, blocks_list = asyncio.run(_drive())

    # C-31: one node per block (count derived from the run, not asserted blind).
    assert node_count == len(blocks)
    # A CRC node renders (head names the crc kind) …
    assert any("crc" in h for h in heads), f"no CRC node head; heads={heads}"
    # … and its post-run summary reports the injection (status/message shows).
    assert any(
        "injected" in s and "CRC" in s for s in summaries
    ), f"no CRC injection summary; summaries={summaries}"
    # The pre-run block list surfaces the CRC label + its config_ref (LLR-093.2).
    assert "CRC" in blocks_list and "crc.json" in blocks_list, blocks_list
