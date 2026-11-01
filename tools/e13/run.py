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
  ld-dialog       Load project P via ``action_load_project`` (key ``p``): the
                  Load dialog stays open with P highlighted and its
                  ``firmware`` variant marked, beside Q, two work-area files
                  and one recorded recent source (CASE02). ``--close`` does
                  not apply.
  lq-question     Load CASE01 through the loader, apply one Patch Editor
                  entry the way the test helper ``add_and_apply`` does (same
                  widget ids, same values, D true), then start a project
                  load of P through ``_route_load_project("P")``: the replace
                  question (``ConfirmQuestionScreen``) stays open,
                  unanswered. ``--close`` does not apply.
  sd-dialog       Load project P (the clean manifest, as pe-clean), then
                  open the Save project dialog (``ctrl+s``) and replace the
                  prefilled name with ``P2`` (a new folder): the dialog
                  stays open painting the "new project" plan for P2.
                  ``--close`` does not apply.

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
             "pe-unreadable", "pe-document", "pe-a2l-only", "wa-files", "ld-dialog",
             "lq-question", "sd-dialog")


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
    if scenario == "wa-files":
        # Inc 9a: Workarea Files rows painted literally (LLR-172.6), names
        # ending in a dot or space left out (LLR-172.4d).
        temp = workarea / "temp"
        temp.mkdir()
        for name in ("plain.s19", "[b]markup[red]text.s19", "fw\u202egpj.s19",
                     "x" * 130 + ".s19", "del\x7fname.s19", "dot.s19.", "space.s19 "):
            # The long-path prefix keeps the 134-character name and the
            # trailing dot or space that Win32 would otherwise strip.
            shutil.copy2(CASE01, "\\\\?\\" + str(temp / name))
    if scenario == "ld-dialog":
        # Load dialog (key p): P is the clean manifest (as pe-clean), Q a
        # copy of P, and the temp folder carries fw.s19 / cal.a2l as
        # work-area files. The recent-sources store is written through
        # record_recent_source in build_app.
        shutil.copytree(project, workarea / "Q")
        temp = workarea / "temp"
        temp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CASE01, temp / "fw.s19")
        shutil.copy2(CASE01.with_name("firmware.a2l"), temp / "cal.a2l")
    if scenario == "lq-question":
        # The replace-question surface: P is the clean manifest (as
        # pe-clean), and the temp folder holds fw2.s19 (a CASE02 copy) as
        # a work-area file. The driver loads CASE01 itself and patches it,
        # so P must stay a clean one-variant project.
        temp = workarea / "temp"
        temp.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CASE02, temp / "fw2.s19")
    text = json.dumps(manifest, indent=2)
    if scenario == "pe-damaged":
        text = '{"schema_version": 1, "active_variant": '
    (project / "project.json").write_text(text, encoding="utf-8")


def build_app(base: Path, scenario: str, close: bool):
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.workspace import (
        WORKAREA_DIRNAME,
        WORKAREA_SUBDIR,
        record_recent_source,
    )

    seed(base / WORKAREA_DIRNAME / WORKAREA_SUBDIR, scenario)
    if scenario in ("ld-dialog", "lq-question"):
        # The recent-sources store lives under %LOCALAPPDATA%; point it at a
        # scratch folder under --base so the real one is never touched
        # (capture.ps1 does not set LOCALAPPDATA). ld-dialog records a
        # recent source directly; lq-question records CASE01 through
        # load_from_path. The capture script deletes --base afterwards, so
        # this folder is cleaned up with it.
        lad = base / "lad"
        lad.mkdir(parents=True, exist_ok=True)
        os.environ["LOCALAPPDATA"] = str(lad)

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
            # Run the drive as its own task (not through call_after_refresh)
            # so the Textual message loop stays free to dispatch the button
            # presses the drive posts (Patch Editor Add / Apply). A drive
            # scheduled through call_after_refresh runs inside the message
            # loop and blocks it across its awaits, so those messages would
            # only be processed after the drive had already asked the
            # question.
            self._e13_drive_task = asyncio.create_task(self._e13_drive())

        async def _e13_drive(self) -> None:
            try:
                await asyncio.sleep(0.5)
                if scenario == "ld-dialog":
                    # Record one recent source through the app's own store
                    # API (LLR-172.1a), then open the Load dialog the way
                    # key ``p`` does, and leave it open with P highlighted.
                    record_recent_source(CASE02)
                    self.action_load_project()
                    for _ in range(60):
                        if type(self.screen).__name__ == "LoadDialog":
                            break
                        await asyncio.sleep(0.1)
                    await asyncio.sleep(0.5)
                elif scenario == "lq-question":
                    from textual.widgets import Input

                    # 1. Load CASE01 through the loader (the copy lands in
                    # workarea/temp) and wait until the image is installed.
                    self.load_from_path(CASE01)
                    for _ in range(60):
                        cur = self.current_file
                        if cur is not None and Path(cur.path).name == "firmware.s19":
                            break
                        await asyncio.sleep(0.1)
                    await asyncio.sleep(0.4)
                    # 2. One Patch Editor entry, exactly as the test helper
                    # add_and_apply does: same widget ids, same values
                    # (0x8000007C <- DE AD BE EF), then Apply (D true).
                    self.action_show_screen("patch")
                    for _ in range(30):
                        if len(self.query("#patch_entry_add_button")) > 0:
                            break
                        await asyncio.sleep(0.1)
                    self.query_one("#patch_entry_address_input", Input).value = ""
                    self.query_one("#patch_entry_bytes_input", Input).value = ""
                    self.query_one("#patch_entry_address_input", Input).value = "0x8000007C"
                    self.query_one("#patch_entry_bytes_input", Input).value = "DE AD BE EF"
                    self.query_one("#patch_entry_add_button").press()
                    for _ in range(30):
                        if len(self._change_service.document.entries) >= 1:
                            break
                        await asyncio.sleep(0.1)
                    self.query_one("#patch_doc_apply_button").press()
                    for _ in range(30):
                        cur = self.current_file
                        if cur is not None and self._change_service.differs_from_last_saved(cur.mem_map):
                            break
                        await asyncio.sleep(0.1)
                    await asyncio.sleep(0.2)
                    # 3. Start a project load of P through the guarded
                    # route, and leave the replace question open.
                    self._route_load_project("P")
                    for _ in range(60):
                        if type(self.screen).__name__ == "ConfirmQuestionScreen":
                            break
                        await asyncio.sleep(0.1)
                    await asyncio.sleep(0.5)
                elif scenario == "sd-dialog":
                    from textual.widgets import Input

                    # 1. Load project P the way the tests do: the guarded
                    # route runs the load and opens the Load-result panel.
                    self._route_load_project("P")
                    for _ in range(60):
                        if type(self.screen).__name__ == "LoadResultScreen":
                            break
                        await asyncio.sleep(0.1)
                    if type(self.screen).__name__ == "LoadResultScreen":
                        # Let the panel finish mounting before dismissing it
                        # (the same settle the ``--close`` drive uses).
                        await asyncio.sleep(0.5)
                        self.screen.dismiss(None)
                    for _ in range(60):
                        if self.current_project == "P":
                            break
                        await asyncio.sleep(0.1)
                    await asyncio.sleep(0.3)
                    # 2. Open the Save project dialog (key ctrl+s).
                    self.action_save_project()
                    for _ in range(60):
                        if type(self.screen).__name__ == "SaveProjectScreen":
                            break
                        await asyncio.sleep(0.1)
                    # 3. The first preview paints after the first frame and
                    # its 150 ms debounce; wait for it, then replace the
                    # prefilled name with P2 (a new folder) so the preview
                    # recomputes, and leave the dialog open.
                    await asyncio.sleep(1.0)
                    field = self.screen.query_one("#project_name", Input)
                    self.screen.set_focus(field)
                    field.value = "P2"
                    await asyncio.sleep(1.0)
                else:
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
