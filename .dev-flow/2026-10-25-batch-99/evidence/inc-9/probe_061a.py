import asyncio
import sys
from pathlib import Path
import tempfile

sys.path.insert(0, "tests")
from test_before_after_report import (
    _make_s19_image,
    _load_image,
    _drive_apply,
    _set_entry_inputs,
)
from s19_app.tui.app import S19TuiApp


def test_probe(tmp_path):
    image_path = _make_s19_image(tmp_path)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj"
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel")
            print("summary after load:", app._change_service.last_summary)
            await _drive_apply(app, pilot)
            print("summary after apply:", app._change_service.last_summary is not None)
            app.query_one("#patch_saveback_confirm_button").press()
            await pilot.pause()
            print("summary after saveback:", app._change_service.last_summary is not None)
            _set_entry_inputs(app, address="0x108", bytes_text="CC DD")
            panel.request_action("add_entry")
            await pilot.pause()
            s = app._change_service.last_summary
            print("summary after add_entry:", s is not None)
            from textual.widgets import Button
            button = panel.query_one("#patch_before_after_button", Button)
            button.press()
            await pilot.pause()
            s = app._change_service.last_summary
            print("summary after button press:", s is not None)
            for w in ("#log_line_1", "#log_line_2", "#log_line_3", "#log_line_4"):
                from textual.widgets import Label
                try:
                    print(w, repr(str(app.query_one(w, Label).render())))
                except Exception as e:
                    print(w, "ERR", type(e).__name__, e)

    asyncio.run(_drive())


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        test_probe(Path(d))
