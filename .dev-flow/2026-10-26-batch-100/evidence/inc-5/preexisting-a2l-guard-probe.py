import asyncio, shutil, sys, tempfile
from pathlib import Path
sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app-b100-inc5")
from tests.test_b100_save_image import *  # noqa
from tests.test_b100_save_image import _load_project, _save, CASE01_DIR

tmp = Path(tempfile.mkdtemp())


async def main():
    app = S19TuiApp(base_dir=tmp / "app")
    p1 = app.workarea / "P1"
    p1.mkdir(parents=True)
    for name in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copy2(CASE01_DIR / name, p1 / name)
    async with app.run_test(size=(220, 60)) as pilot:
        await pilot.pause()
        await _load_project(pilot, app, "P1")
        print("path", app.current_file.path, "mac", app.current_file.mac_path, "a2l", app.current_a2l_path)
        await _save(pilot, app, "P1")
        for _ in range(60):
            await pilot.pause()
        for line in list(app.log_lines)[-8:]:
            print("LOG", line)

asyncio.run(main())
