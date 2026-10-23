"""P08: the Patch Editor save-back stages its bytes at <workarea>/temp/<typed name>
and unlinks the stage afterwards (changes/apply.py). When the typed name equals
the loaded image's work-copy name, the work copy itself is overwritten and then
deleted. Then Save project is driven THROUGH THE MESSAGE LOOP (the real Save
dialog dismissing with a payload), to see what the running app does when the
callback raises."""
from common import *
from s19_app.tui.screens import SaveProjectScreen, SaveProjectPayload


async def main():
    base = new_base()
    app = new_app(base)
    crashed = None
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            await settle(app, pilot)
            await load_path(app, pilot, C1 / "firmware.s19")
            work = app.current_file.path
            print("work copy:", work.relative_to(app.workarea).as_posix(), "exists:", work.exists())
            patch_apply(app, hex(max(app.current_file.mem_map) - 3), "DE AD BE EF")
            from s19_app.tui.screens_directionb import PatchEditorPanel as Pn
            app.on_patch_editor_panel_save_back_decision(Pn.SaveBackDecision("firmware.s19"))
            await settle(app, pilot)
            print("save-back status:", app._probe_status[-2:])
            print("work copy exists after save-back:", work.exists(), "| app still holds:", app.current_file.path.relative_to(app.workarea).as_posix())
            print("workarea files:", sorted(p.relative_to(app.workarea).as_posix() for p in app.workarea.rglob("*") if p.is_file()))
            screen = SaveProjectScreen(app.workarea)
            app.push_screen(screen, app._handle_save_dialog)
            await settle(app, pilot)
            screen.dismiss(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
            await settle(app, pilot, n=10)
            print("after Save-project dismiss: app running?", app.is_running, "| return_code:", app.return_code)
    except Exception as exc:  # noqa: BLE001
        crashed = exc
    print("run_test outcome:", "EXCEPTION " + type(crashed).__name__ + ": " + str(crashed)[:160] if crashed else "no exception",
          "| app.return_code:", app.return_code)
    print("P folder left behind:", [p.relative_to(base).as_posix() for p in (base / ".s19tool/workarea/P").rglob("*")] if (base / ".s19tool/workarea/P").exists() else "absent")


asyncio.run(main())
