"""Inc 1b E5 capture driver (batch-103, HT-10): the REAL app, isolated state.

Run by capture_i1b.ps1 under ``python -I -B`` in a fresh Windows Terminal
window. Shows one Inc 1b surface per scenario on the tracked public example
A2L (``ASAP2_Demo_V171.a2l`` + ``prg.s19``), read from the checkout.

The OS clipboard is NEVER touched: ``write_os_clipboard`` is replaced by a
fixed True/False stub and the toolkit ``App.copy_to_clipboard`` (which would
emit an OSC 52 request that Windows Terminal may honour) is replaced by a
mirror-only stub. Everything above that (the app's copy entry point, the
tail, the notices, the quit dialog) is the product code.

Scenarios: copy-notice (OS write succeeds -> information notice), write-fail
(OS write fails -> warning), nul-refusal (NUL payload -> warning, no write),
quit-dialog (Ctrl+C with nothing selected -> "Quit?" dialog).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

SCEN = ("copy-notice", "write-fail", "nul-refusal", "quit-dialog")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--scenario", required=True, choices=SCEN)
    ap.add_argument("--base", required=True, type=Path)
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))

    from textual import events
    from textual.app import App
    from textual.widgets import DataTable

    import s19_app.tui.os_clipboard_input as oci
    from s19_app.tui.app import S19TuiApp

    writes: list[int] = []

    def fake_write(text: str) -> bool:
        writes.append(len(text))
        return args.scenario != "write-fail"

    def mirror_only(self, text: str) -> None:  # no OSC 52 to the terminal
        self._clipboard = text

    oci.write_os_clipboard = fake_write
    App.copy_to_clipboard = mirror_only

    base = args.base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    ex = root / "examples" / "case_00_public"
    lines = [f"scenario={args.scenario}", "os_clipboard=stubbed (never touched)", "osc52=stubbed"]

    class CaptureApp(S19TuiApp):
        CSS_PATH = str(root / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)

        def on_mount(self) -> None:
            super().on_mount()
            self._task = asyncio.create_task(self._drive())

        async def _wait(self, pred, timeout=30.0) -> bool:
            end = time.perf_counter() + timeout
            while time.perf_counter() < end:
                if pred():
                    return True
                await asyncio.sleep(0.05)
            return False

        async def _drive(self) -> None:
            try:
                await asyncio.sleep(0.3)
                self.load_selected_file(ex / "prg.s19")
                if not await self._wait(lambda: self.current_file is not None):
                    raise TimeoutError("image load")
                await asyncio.sleep(0.4)
                self.load_a2l_from_path(ex / "ASAP2_Demo_V171.a2l")
                if not await self._wait(
                    lambda: self.current_a2l_data is not None
                    and self._a2l_enriched_key is not None
                    and bool(self._a2l_enriched_tags)
                ):
                    raise TimeoutError("a2l load")
                await asyncio.sleep(0.6)
                self.action_show_screen("a2l")
                await asyncio.sleep(0.6)
                table = self.query_one("#a2l_tags_list", DataTable)
                table.focus()
                table.move_cursor(row=2)
                await asyncio.sleep(0.4)
                name = self._a2l_filtered_tags[2]["name"]
                if args.scenario in ("copy-notice", "write-fail"):
                    self.copy_to_clipboard(name)  # the entry a valid right-click on a row calls
                    ok = await self._wait(lambda: len(self._notifications) > 0, 5.0)
                    if not ok:
                        raise AssertionError("no notice appeared")
                elif args.scenario == "nul-refusal":
                    self.copy_to_clipboard("VISIBLE\x00SECRET-SUFFIX")
                    ok = await self._wait(lambda: len(self._notifications) > 0, 5.0)
                    if not ok:
                        raise AssertionError("no notice appeared")
                else:
                    self.post_message(events.Key("ctrl+c", None))
                    cls = lambda: type(self.screen).__name__
                    if not await self._wait(lambda: cls() == "_CopyQuitScreen", 5.0):
                        raise AssertionError(f"quit dialog not top (top={cls()})")
                await asyncio.sleep(0.5)
                for n in list(self._notifications):
                    lines.append(f"notice severity={n.severity} message={n.message}")
                lines.append(f"top_screen={type(self.screen).__name__}")
                lines.append(f"stub_os_writes={len(writes)} lengths={writes}")
                lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001
                lines.append(f"surface=error {type(exc).__name__}: {exc}")
            finally:
                if args.report is not None:
                    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
