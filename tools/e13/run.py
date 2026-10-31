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
  pe-patched      Load project P: firmware_1.s19 carries a derived_from record
                  and every file a files record (the "patched, N bytes differ
                  from <base>" line, Inc 7)
  pe-unreadable   Load project P whose active variant broken.s19 holds no S19
                  data (the red "not readable" mark; Load opens the next
                  valid variant, Inc 7)
  pe-document     Load project P whose recorded change document
                  patches/boost.json holds 1 001 entries (the "change document
                  … not readable, too large to reopen" row, Inc 8a)
  pe-a2l-only     Load project P holding only firmware.a2l (with its files
                  record) -> the panel's A2L slot names it with its tag
                  count, no image (D-5, AT-B100-10, Inc 8b)

``--close`` dismisses the panel after it opens, so the capture shows the
summary line and ``#status_text`` the load left behind.

  python tools/e13/run.py --scenario pe-saveback --base <scratch dir>
  python tools/e13/run.py --scenario pe-problems --base <dir> --selftest
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
CASE02 = ROOT / "examples" / "case_02_gaps_and_patch_targets" / "firmware.s19"
SCENARIOS = ("pe-clean", "pe-saveback", "pe-problems", "pe-damaged", "pe-patched",
             "pe-unreadable", "pe-document", "pe-a2l-only")


def seed(workarea: Path, scenario: str) -> None:
    """Project ``P`` on disk in the state the scenario names."""
    project = workarea / "P"
    project.mkdir(parents=True)
    if scenario == "pe-a2l-only":
        a2l = project / "firmware.a2l"
        shutil.copy2(CASE01.with_name("firmware.a2l"), a2l)
        record = {"size": a2l.stat().st_size,
                  "sha256": hashlib.sha256(a2l.read_bytes()).hexdigest()}
        (project / "project.json").write_text(
            json.dumps({"schema_version": 1, "files": {"firmware.a2l": record}}, indent=2),
            encoding="utf-8",
        )
        return
    shutil.copy2(CASE01, project / "firmware.s19")
    manifest: object = {"schema_version": 1, "active_variant": "firmware"}
    if scenario in ("pe-saveback", "pe-problems", "pe-patched"):
        shutil.copy2(CASE02, project / "firmware_1.s19")
        manifest = {"schema_version": 1, "active_variant": "firmware_1"}
    if scenario == "pe-problems":
        manifest["batch"] = [f"../escape_{i:02d}.json" for i in range(30)]
    if scenario == "pe-patched":
        base_sha = hashlib.sha256((project / "firmware.s19").read_bytes()).hexdigest()
        manifest["files"] = {
            item.name: {
                "size": item.stat().st_size,
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
            }
            for item in sorted(project.glob("*.s19"))
        }
        manifest["derived_from"] = {
            "firmware_1.s19": {"base": "firmware.s19", "sha256": base_sha, "differ": 4}
        }
    if scenario == "pe-unreadable":
        (project / "broken.s19").write_text("not an s19 file\n", encoding="utf-8")
        manifest["active_variant"] = "broken"
    if scenario == "pe-document":
        (project / "patches").mkdir()
        entries = [{"address": "0x0", "data": "00"}] * 1001
        (project / "patches" / "boost.json").write_text(
            json.dumps({"entries": entries}), encoding="utf-8"
        )
        manifest["active_document"] = "patches/boost.json"
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
