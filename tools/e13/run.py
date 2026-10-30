"""E13 runner — the real app on a scratch work area, driven to one surface.

Batch-100 enabler E13 (C-UX-5). ``capture.ps1`` starts this file inside a new
Windows Terminal window, with ``PYTHONPATH`` set to the tree under test, and
saves the window as a PNG. The runner builds its own work area under
``--base`` (the capture script creates that folder and deletes it after the
window closes), opens the app on it and drives one scenario through the same
handlers a keyboard user reaches.

Scenarios:
  pe-clean        Load project P (one variant, a clean manifest) -> the panel
  pe-saveback     Load project P after a save-back (firmware_1.s19 active)
  pe-problems     Load project P with 30 problems -> the panel lists all 30
  pe-damaged      Load project P whose project.json is not JSON

``--close`` dismisses the panel after it opens, so the capture shows the
summary line and ``#status_text`` the load left behind.

  python tools/e13/run.py --scenario pe-saveback --base <scratch dir>
  python tools/e13/run.py --scenario pe-problems --base <dir> --selftest
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
CASE02 = ROOT / "examples" / "case_02_gaps_and_patch_targets" / "firmware.s19"
SCENARIOS = ("pe-clean", "pe-saveback", "pe-problems", "pe-damaged")


def seed(workarea: Path, scenario: str) -> None:
    """Project ``P`` on disk in the state the scenario names."""
    project = workarea / "P"
    project.mkdir(parents=True)
    shutil.copy2(CASE01, project / "firmware.s19")
    manifest: object = {"schema_version": 1, "active_variant": "firmware"}
    if scenario in ("pe-saveback", "pe-problems"):
        shutil.copy2(CASE02, project / "firmware_1.s19")
        manifest = {"schema_version": 1, "active_variant": "firmware_1"}
    if scenario == "pe-problems":
        manifest["batch"] = [f"../escape_{i:02d}.json" for i in range(30)]
    text = json.dumps(manifest, indent=2)
    if scenario == "pe-damaged":
        text = '{"schema_version": 1, "active_variant": '
    (project / "project.json").write_text(text, encoding="utf-8")


def build_app(base: Path, scenario: str, close: bool):
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

    seed(base / WORKAREA_DIRNAME / WORKAREA_SUBDIR, scenario)

    class E13App(S19TuiApp):
        # Textual resolves a relative CSS_PATH against the subclass's own
        # file; point it back at the app's stylesheet in the tree under test.
        CSS_PATH = str(ROOT / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)
            self.title = f"E13-{scenario}" + ("-closed" if close else "")
            self.e13_ready = asyncio.Event()

        def on_mount(self) -> None:
            super().on_mount()
            self.call_after_refresh(self._e13_drive)

        async def _e13_drive(self) -> None:
            try:
                await asyncio.sleep(0.5)
                # The Load project dialog's own dismiss callback: the route
                # that opens the Load-result panel (LLR-178.3).
                self._route_load_project("P")
                for _ in range(60):
                    if type(self.screen).__name__ == "LoadResultScreen":
                        break
                    await asyncio.sleep(0.1)
                if close and type(self.screen).__name__ == "LoadResultScreen":
                    await asyncio.sleep(0.5)
                    self.screen.dismiss(None)
                await asyncio.sleep(0.5)
            finally:
                self.e13_ready.set()

    return E13App()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--close", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    base = args.base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    app = build_app(base, args.scenario, args.close)
    if not args.selftest:
        app.run()
        return
    import s19_app

    async def _once() -> None:
        async with app.run_test(size=(118, 54)) as pilot:
            await app.e13_ready.wait()
            await pilot.pause()
            print("s19_app:", s19_app.__file__)
            print("screen:", type(app.screen).__name__)
            print("status:", list(app.log_lines)[-2:])

    asyncio.run(_once())
    print(f"SELFTEST OK scenario={args.scenario} close={args.close}")


if __name__ == "__main__":
    main()
