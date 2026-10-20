"""Probe (Code-Wire PDR annex, not product): after the confirm re-run of a lane with
TWO external-step blocks, does the panel still show the lane waiting and its Confirm?"""
import asyncio, json
from pathlib import Path
import s19_app
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import (
    EXTERNAL_MODE_TERMINAL, ExternalStepBlock, Flow, SourceBlock, WriteOutBlock)

_S19 = "S107100001020304DE\nS9030000FC\n"

def test_probe_two_ext(tmp_path: Path) -> None:
    project = tmp_path / ".s19tool" / "workarea" / "proj"
    project.mkdir(parents=True)
    (project / "base.s19").write_text(_S19, encoding="utf-8")
    ext_dir = tmp_path / "externo"; ext_dir.mkdir()
    b1 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="step one",
                           log_ref="run1.log", output_path=str(ext_dir / "out1.s19"))
    b2 = ExternalStepBlock(mode=EXTERNAL_MODE_TERMINAL, instruction="step two",
                           log_ref="run2.log", output_path=str(ext_dir / "out2.s19"))
    fps.save_flow_json(Flow(name="ext2", blocks=[SourceBlock("base.s19"), b1, b2,
                       WriteOutBlock("out.s19")]), "ext2", project)

    async def drive():
        from textual.widgets import Button, Static
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            app.action_show_screen("flow_execution")
            await pilot.pause()
            app.query_one("#fx_import", Button).press()
            for _ in range(50):
                await pilot.pause()
                try:
                    app.screen.query_one("#flow_load_ok", Button); break
                except Exception:
                    continue
            items = app.screen.query_one("#flow_list")
            for i, item in enumerate(items.query("ListItem")):
                if item.name == "ext2":
                    items.index = i; break
            app.screen.query_one("#flow_load_ok", Button).press()
            await pilot.pause(); await pilot.pause()
            app.query_one("#fx_run", Button).press()
            for _ in range(40):
                await pilot.pause()
            panel = app.query_one("#fx_panel")
            first = (panel._lanes[0].paused_block, app.query_one("#fx_confirm_0", Button).display)
            (project / "run1.log").write_text("ok\n", encoding="utf-8")
            (ext_dir / "out1.s19").write_text(_S19, encoding="utf-8")
            app.query_one("#fx_confirm_0", Button).press()
            for _ in range(40):
                await pilot.pause()
            rec = panel.last_run_record
            second = (panel._lanes[0].paused_block, app.query_one("#fx_confirm_0", Button).display,
                      panel._lanes[0].last_status)
            log = app.query_one("#fx_log", Static).render().plain
            return first, second, log
    first, second, log = asyncio.run(drive())
    print("\nS19_APP_FROM", s19_app.__file__)
    print("FIRST_RUN paused_block, confirm_display =", first)
    print("AFTER_CONFIRM paused_block, confirm_display, last_status =", second)
    print("RUN_LOG_TAIL", log.strip().splitlines()[-3:])
