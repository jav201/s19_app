"""Inc 10 E5 capture driver (batch-103, HT-10 / X10): the REAL app, isolated state, real keys.

Run by capture_i10.ps1 under ``python -I -B`` in a fresh Windows Terminal window (a copy of CAP8's
``inc-8/evidence/captures/capture_i8_driver.py`` method: same sidecar, ``surface=ready``, release flag). It drives
the Patch Editor's save-back dock to the state one capture item asks for, through the app's own key handling
(``App._press_keys``, the call Textual's pilot uses): a widget is focused and Enter is pressed, characters are
typed key by key. Then it writes a sidecar of the state it actually reached.

Fixture data only: ``examples/case_01_basic_valid/firmware.s19`` (case01), copied into the scratch base first so no
checkout path is loaded or painted; the entry is case01's inside entry 0x8000007C ``DE AD BE EF`` (the Inc 10
cases' PATCH entry). ``numbered`` seeds ``firmware-patched.s19`` (one S0 line, other content) in the work area
before ``Write file``, so the placement lands on the numbered name.

The OS clipboard is never touched: ``write_os_clipboard`` and ``App.copy_to_clipboard`` are stubbed.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import time
from pathlib import Path

SCEN = ("idle", "applied", "format-hex", "format-s19", "numbered")
ADDRESS = "0x8000007C"
BYTES = "DE AD BE EF"
DOCK_IDS = (
    "patch_doc_controls", "patch_export_dock", "patch_saveback_row", "patch_saveback_apply_line",
    "patch_saveback_name_input", "patch_saveback_format_button", "patch_saveback_width_button",
    "patch_saveback_confirm_button", "patch_saveback_decline_button", "patch_before_after_row",
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--scenario", required=True, choices=SCEN)
    ap.add_argument("--base", required=True, type=Path)
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--release", type=Path, default=None)
    args = ap.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))

    from textual.app import App
    from textual.widgets import Button, Input, Static

    import s19_app.tui.os_clipboard_input as oci
    from s19_app.tui.app import S19TuiApp

    writes: list[int] = []

    def fake_write(text: str) -> bool:
        writes.append(len(text))
        return True

    def mirror_only(self, text: str) -> None:
        self._clipboard = text

    oci.write_os_clipboard = fake_write
    App.copy_to_clipboard = mirror_only

    base = args.base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    scen = args.scenario
    source = base / "firmware.s19"
    shutil.copyfile(root / "examples" / "case_01_basic_valid" / "firmware.s19", source)

    lines = [
        f"scenario={scen}",
        "fixture=examples/case_01_basic_valid/firmware.s19 (case01), copied into the scratch base",
        f"entry={ADDRESS} {BYTES}",
        "os_clipboard=stubbed (never touched)",
        "osc52=stubbed",
    ]
    statuses: list[str] = []

    class CaptureApp(S19TuiApp):
        CSS_PATH = str(root / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)

        def set_status(self, message: str) -> None:
            statuses.append(message)
            super().set_status(message)

        def on_mount(self) -> None:
            super().on_mount()
            self._task = asyncio.create_task(self._drive())

        # ---- helpers -------------------------------------------------- #

        async def _wait(self, pred, timeout=30.0) -> bool:
            end = time.perf_counter() + timeout
            while time.perf_counter() < end:
                if pred():
                    return True
                await asyncio.sleep(0.05)
            return False

        async def press(self, *keys: str, pause: float = 0.2) -> None:
            await self._press_keys(keys)
            await asyncio.sleep(pause)

        def panel(self):
            return self.query_one("#patch_editor_panel")

        async def enter_on(self, selector: str, pause: float = 0.6) -> None:
            """Focus the widget and press Enter through the app's key handling."""
            widget = self.panel().query_one(selector)
            widget.focus()
            await asyncio.sleep(0.3)
            if self.focused is not widget:
                raise AssertionError(f"{selector} did not take focus (focus {self.focused})")
            await self.press("enter", pause=pause)

        async def type_into(self, selector: str, text: str) -> None:
            box = self.panel().query_one(selector, Input)
            box.focus()
            await asyncio.sleep(0.3)
            await self.press("ctrl+a", "delete", pause=0.1)
            for ch in text:
                await self.press("space" if ch == " " else ch, pause=0.05)
            await asyncio.sleep(0.3)

        async def until_status(self, prefix: str, seen: int, timeout: float = 30.0) -> str:
            if not await self._wait(lambda: any(s.startswith(prefix) for s in statuses[seen:]), timeout):
                raise TimeoutError(f"no status starting {prefix!r}; last {statuses[-3:]}")
            await asyncio.sleep(0.6)
            return next(s for s in statuses[seen:] if s.startswith(prefix))

        def dock_facts(self) -> None:
            from textual.errors import NoWidget

            panel = self.panel()
            switcher = panel.query_one("#patch_tab_switcher")
            lines.append(f"shown_pane={switcher.current}")
            row = panel.query_one("#patch_saveback_row")
            lines.append(f"prompt_hidden_class={row.has_class('hidden')}")
            lines.append("apply_line=" + str(panel.query_one("#patch_saveback_apply_line", Static).render()))
            lines.append("format_label=" + str(panel.query_one("#patch_saveback_format_button", Button).label))
            width = panel.query_one("#patch_saveback_width_button", Button)
            lines.append(f"width_label={width.label} visibility={width.styles.visibility}")
            lines.append("name_box=" + panel.query_one("#patch_saveback_name_input", Input).value)
            for wid in DOCK_IDS:
                widget = panel.query_one(f"#{wid}")
                try:
                    seen = self.screen.find_widget(widget).visible_region
                except NoWidget:
                    seen = None
                hit = self.get_widget_at(*seen.center)[0] if seen is not None and seen.area else None
                lines.append(f"painted {wid}: {seen} hit_at_centre={getattr(hit, 'id', None)}")
            strips = self.screen._compositor.render_strips()
            top = panel.query_one("#patch_doc_controls").region.y
            lines.append("painted_rows_from_document_row_begin")
            for y in range(top, min(top + 8, len(strips))):
                lines.append("  " + "".join(s.text for s in strips[y]).rstrip())
            lines.append("painted_rows_from_document_row_end")

        # ---- the drive ------------------------------------------------ #

        async def _drive(self) -> None:
            try:
                await asyncio.sleep(0.5)
                self.load_from_path(source)
                if not await self._wait(lambda: self.current_file is not None, 30.0):
                    raise TimeoutError("image load")
                await asyncio.sleep(0.5)
                self.action_show_screen("patch")
                await asyncio.sleep(1.2)
                lines.append(f"app_size={self.size.width}x{self.size.height}")
                await self.enter_on("#patch_tab_inspector")
                await self.type_into("#patch_entry_address_input", ADDRESS)
                await self.type_into("#patch_entry_bytes_input", BYTES)
                seen = len(statuses)
                await self.enter_on("#patch_entry_add_button")
                lines.append("status_after_add=" + await self.until_status("Patch Editor: entry added", seen))
                if scen != "idle":
                    seen = len(statuses)
                    await self.enter_on("#patch_doc_apply_button")
                    lines.append("status_after_apply=" + await self.until_status("Apply:", seen))
                if scen in ("format-hex", "format-s19"):
                    await self.enter_on("#patch_saveback_format_button")
                if scen == "format-s19":
                    await self.enter_on("#patch_saveback_format_button")
                if scen == "numbered":
                    seeded = self.workarea / "firmware-patched.s19"
                    seeded.write_text("S0030000FC\n", encoding="ascii", newline="\n")
                    lines.append("seeded=firmware-patched.s19 (one S0 line, other content) in the work area")
                    seen = len(statuses)
                    await self.enter_on("#patch_saveback_confirm_button", pause=1.0)
                    lines.append("status_after_write=" + await self.until_status("Saved", seen))
                    names = sorted(p.name for p in self.workarea.iterdir() if p.name.startswith("firmware-patched"))
                    lines.append("workarea_firmware_patched=" + ", ".join(names))
                    written = self.workarea / "firmware-patched_1.s19"
                    if written.exists():
                        first = written.read_text(encoding="ascii").splitlines()[0]
                        data = bytes.fromhex(first[8:-2])
                        lines.append(f"written_first_line={first} s0_data={data.decode('ascii', 'replace')}")
                await asyncio.sleep(0.6)
                self.dock_facts()
                lines.append(f"focused={getattr(self.focused, 'id', None) or type(self.focused).__name__}")
                lines.append(f"notifications={len(self._notifications)}")
                for s in statuses[-6:]:
                    lines.append(f"status: {s}")
                lines.append(f"stub_os_writes={len(writes)}")
                lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001
                import traceback
                lines.append(f"surface=error {type(exc).__name__}: {exc}")
                lines.extend("  " + ln for ln in traceback.format_exc().splitlines()[-8:])
            finally:
                if args.report is not None:
                    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
                # Stay on screen until the launcher has taken its PNG, then exit 0 on our own so the
                # window we opened closes itself (the process we started ends; nothing is closed by title).
                if args.release is not None:
                    await self._wait(lambda: args.release.exists(), 180.0)
                self.exit(0)

    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
