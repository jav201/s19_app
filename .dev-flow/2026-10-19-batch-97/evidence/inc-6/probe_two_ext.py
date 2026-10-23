"""Inc-6 gate probe (design §6.1 Inc-6 item (4); Code-Wire PDR next step 5):
the Code-Wire probe ``design/codewire/extract/probe_two_ext.py`` extended with
the SECOND confirm. A lane with two external steps: run → waits at its first
step; confirm → it must wait at its SECOND step with Confirm shown; confirm
again → the lane must end ``ok`` (it must not bounce back to its first wait).

Usage: python probe_two_ext.py <tree root>   (HEAD worktree, or the Inc-6 tree)
Evidence, not product: no assertion — it prints what the tree does.
"""
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))

import s19_app  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.services import flow_persistence_service as fps  # noqa: E402
from s19_app.tui.services.flow_model import (  # noqa: E402
    EXTERNAL_MODE_TERMINAL,
    ExternalStepBlock,
    Flow,
    SourceBlock,
    WriteOutBlock,
)

_S19 = "S107100001020304DE\nS9030000FC\n"


async def pump(pilot, n=40):
    for _ in range(n):
        await pilot.pause()


async def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    project = tmp / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    (project / "base.s19").write_text(_S19, encoding="utf-8")
    ext_dir = tmp / "externo"
    ext_dir.mkdir()
    b1 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="step one", log_ref="run1.log", output_path=str(ext_dir / "out1.s19"))
    b2 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="step two", log_ref="run2.log", output_path=str(ext_dir / "out2.s19"))
    fps.save_flow_json(Flow(name="ext2", blocks=[SourceBlock("base.s19"), b1, b2, WriteOutBlock("out.s19")]), "ext2", project)
    for log, out in (("run1.log", "out1.s19"), ("run2.log", "out2.s19")):
        (project / log).write_text("ok\n", encoding="utf-8")
        (ext_dir / out).write_text(_S19, encoding="utf-8")
    app = S19TuiApp(base_dir=tmp)
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        app.current_project_dir = project
        app.action_show_screen("flow_execution")
        await pump(pilot, 4)
        app.query_one("#fx_import").press()
        await pump(pilot, 20)
        items = app.screen.query_one("#flow_list")
        for i, item in enumerate(items.query("ListItem")):
            if item.name == "ext2":
                items.index = i
        await pump(pilot, 4)
        app.screen.query_one("#flow_load_ok").press()
        await pump(pilot, 10)
        app.query_one("#fx_run").press()
        await pump(pilot)
        panel = app.query_one("#fx_panel")
        confirm = app.query_one("#fx_confirm_0")
        print("S19_APP_FROM", s19_app.__file__)
        print("FIRST_RUN       paused_block, confirm_display =", (panel._lanes[0].paused_block, confirm.display))
        confirm.press()
        await pump(pilot)
        print("AFTER_CONFIRM_1 paused_block, confirm_display, last_status =",
              (panel._lanes[0].paused_block, confirm.display, panel._lanes[0].last_status))
        if confirm.display and not confirm.disabled:
            confirm.press()
            await pump(pilot)
        print("AFTER_CONFIRM_2 paused_block, confirm_display, last_status =",
              (panel._lanes[0].paused_block, confirm.display, panel._lanes[0].last_status))
        print("RUN_LOG_TAIL", panel.run_log_plain().strip().splitlines()[-4:])


asyncio.run(main())
