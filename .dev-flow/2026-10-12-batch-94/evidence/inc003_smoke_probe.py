"""inc003 smoke probe — the fx_a shipped-surface pastes (C-42 / C-32).

Drives the real S19TuiApp surface (import -> bind two chains -> parallel run
with one failing chain) and pastes, into the transcript:
  * the painted lane box (the C-32 painted oracle),
  * the run-log strip with the inline X line (suggestion #1),
  * the EMITTED chain-set report (the C-42 provenance paste).

Throwaway evidence tooling; not part of the suite. Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
        python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_smoke_probe.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.tui.app import S19TuiApp
from s19_app.tui.flow_screens import FlowExecutionPanel
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import (
    CrcBlock,
    Flow,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from textual.widgets import Button, Input, ListView, Select

S19 = "S107100001020304DE\nS9030000FC\n"


async def main() -> int:
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="inc003smoke"))
    project = tmp / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    (project / "base.s19").write_text(S19, encoding="utf-8")
    (project / "variant_b.hex").write_text(S19, encoding="utf-8")
    (project / "hotfix.json").write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [{"type": "bytes", "address": "0x1001", "bytes": "AA"}],
            }
        ),
        encoding="utf-8",
    )
    fps.save_flow_json(
        Flow(
            name="base",
            blocks=[
                SourceBlock("base.s19"),
                PatchBlock("hotfix.json"),
                WriteOutBlock("base_out.s19"),
            ],
        ),
        "base",
        project,
    )
    fps.save_flow_json(
        Flow(
            name="base_crc",
            blocks=[
                SourceBlock("base.s19"),
                PatchBlock("hotfix.json"),
                CrcBlock("crc_regions.json"),  # absent: the inline-failure arm
                WriteOutBlock("crc_out.s19"),
            ],
        ),
        "base_crc",
        project,
    )

    app = S19TuiApp(base_dir=tmp)
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        app.current_project_dir = project
        app.action_show_screen("flow_execution")
        await pilot.pause()
        panel = app.query_one("#fx_panel", FlowExecutionPanel)

        for stem in ("base", "base_crc"):
            app.query_one("#fx_import", Button).press()
            for _ in range(50):
                await pilot.pause()
                try:
                    app.screen.query_one("#flow_load_ok")
                    break
                except Exception:
                    continue
            items = app.screen.query_one("#flow_list", ListView)
            items.index = next(
                i
                for i, item in enumerate(items.query("ListItem"))
                if item.name == stem
            )
            app.screen.query_one("#flow_load_ok", Button).press()
            await pilot.pause()
            await pilot.pause()

        panel.query_one("#fx_in_1_0", Input).value = "variant_b.hex"
        panel.query_one("#fx_bind_1_0", Button).press()
        await pilot.pause()
        app.query_one("#fx_mode", Select).value = "parallel"
        await pilot.pause()
        app.query_one("#fx_run", Button).press()
        for _ in range(20):
            await pilot.pause()

        print("=== lane 0 paint (C-32) ===")
        print(panel.lane_paint_plain(0))
        print("=== lane 1 paint (C-32) ===")
        print(panel.lane_paint_plain(1))
        print("=== run-log strip (inline X = suggestion #1) ===")
        print(panel.run_log_plain())
        record = panel.last_run_record
        print("=== record ===")
        print("mode:", record.mode)
        for outcome in record.outcomes:
            print(
                f"  {outcome.chain}: status={outcome.status} "
                f"window=({outcome.started_at:.4f}, {outcome.finished_at:.4f}) "
                f"inputs={outcome.inputs}"
            )
        print("=== emitted chain-set report (C-42 paste) ===")
        print(record.report_path.read_text(encoding="utf-8"))
        print("SMOKE OK")
    return 0


sys.exit(asyncio.run(main()))
