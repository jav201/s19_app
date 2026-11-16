"""Inc 8 capture driver (batch-103, HT-10 / CAP8): the REAL app, isolated state, real keys.

Run by capture_i8.ps1 under ``python -I -B`` in a fresh Windows Terminal window. It drives the Patch Editor's
edit-by-definition sheet to the state one capture item asks for, through the app's own key handling
(``App._press_keys``, the call Textual's pilot uses; never a posted widget method), then writes a sidecar of
the state it actually reached and reports ``surface=ready``.

Fixture data only:
  defc  = the synthetic definitions case written by the shipped ``tools/synth/make_release_case.py`` (seed 20260001).
  v171  = the public example A2L ``examples/case_00_public/ASAP2_Demo_V171.a2l`` with a small hand image
          ("Hello ASAM" + NUL) written to the scratch folder at the 42-byte ASCII object's address.
  v171big = that A2L copied to the scratch folder with the ASCII object widened to 5,000 bytes (R-PE-DEF.79).

The OS clipboard is never touched: ``write_os_clipboard`` and ``App.copy_to_clipboard`` are stubbed.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SEED = 20260001
TEXT_NAME = "ASAM.C.ASCII.UBYTE.NUMBER_42"
TEXT_ADDRESS = 0x810200
MARKS = "▶●◆"

SCEN = (
    "layout", "rows", "p046", "number", "notice", "longmsg", "enum", "mask", "text", "curve", "array",
    "refused", "bigtext", "status-staged", "status-notice", "status-overlap", "narrow", "narrow-edit", "help", "help-use", "k1",
    "inspector", "inspector-add",
)
DATASET = {
    "layout": "defc", "rows": "defc", "p046": "defc", "number": "defc", "notice": "defc", "longmsg": "defc",
    "enum": "defc", "mask": "defc", "text": "v171", "curve": "v171", "array": "v171", "refused": "v171",
    "bigtext": "v171big", "status-staged": "defc", "status-notice": "defc", "status-overlap": "defc",
    "narrow": "defc", "narrow-edit": "defc", "help": "defc", "help-use": "defc", "k1": "defc",
    "inspector": "defc", "inspector-add": "defc",
}


def s3_records(address: int, data: bytes) -> list[str]:
    """S0 + S3 records + S7 for ``data`` at ``address`` (checksum = ones complement of the byte sum)."""

    def rec(kind: str, addr_bytes: bytes, payload: bytes) -> str:
        body = bytes([len(addr_bytes) + len(payload) + 1]) + addr_bytes + payload
        return f"{kind}{body.hex().upper()}{(~sum(body)) & 0xFF:02X}"

    lines = [rec("S0", b"\x00\x00", b"cap")]
    for off in range(0, len(data), 32):
        chunk = data[off:off + 32]
        lines.append(rec("S3", (address + off).to_bytes(4, "big"), chunk))
    lines.append(rec("S7", b"\x00\x00\x00\x00", b""))
    return lines


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
    from textual.widgets import DataTable, Input

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
    data = DATASET[scen]

    if data == "defc":
        out = base / "defc"
        subprocess.run(
            [sys.executable, "-B", str(root / "tools" / "synth" / "make_release_case.py"),
             "--out", str(out), "--seed", str(SEED), "--case", "definitions"],
            check=True, capture_output=True, timeout=600,
        )
        a2l_path, s19_path = out / "definitions.a2l", out / "definitions.s19"
        fixture = "definitions case (tools/synth/make_release_case.py --case definitions --seed 20260001)"
    else:
        src = root / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
        a2l_path = src
        size = 42
        if data == "v171big":
            text = src.read_text(encoding="utf-8", errors="replace")
            old = "      NUMBER 42 \n"
            assert text.count(old) == 1, "the ASCII object's NUMBER line moved"
            a2l_path = base / "V171_text5000.a2l"
            a2l_path.write_text(text.replace(old, "      NUMBER 5000 \n"), encoding="utf-8", newline="\n")
            size = 5000
        image = (b"Hello ASAM" + bytes(size))[:size]
        s19_path = base / "hand_image.s19"
        s19_path.write_text("\n".join(s3_records(TEXT_ADDRESS, image)) + "\n", encoding="ascii", newline="\n")
        fixture = (
            "public example A2L examples/case_00_public/ASAP2_Demo_V171.a2l"
            + (" with the ASCII object widened to NUMBER 5000 (scratch copy)" if data == "v171big" else "")
            + f" and a hand image of 'Hello ASAM' + NUL ({size} B) at 0x{TEXT_ADDRESS:X} (scratch S19)"
        )

    lines = [
        f"scenario={scen}",
        f"fixture={fixture}",
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

        async def settle(self, seconds: float = 0.25) -> None:
            await asyncio.sleep(seconds)

        async def press(self, *keys: str, pause: float = 0.2) -> None:
            await self._press_keys(keys)
            await asyncio.sleep(pause)

        def panel(self):
            return self.query_one("#patch_editor_panel")

        def body_text(self) -> str:
            rendered = self.panel().query_one("#patch_sheet_body").render()
            return getattr(rendered, "plain", None) or str(rendered)

        def sheet_text(self) -> str:
            sheet = self.panel().query_one("#patch_sheet")
            parts = []
            for widget in sheet.query("*"):
                if isinstance(widget, Input) or not hasattr(widget, "render") or not widget.display:
                    continue
                if list(widget.children):
                    continue
                rendered = widget.render()
                parts.append(getattr(rendered, "plain", None) or str(rendered))
            return "\n".join(parts)

        def row_lines(self) -> list[tuple[str, str]]:
            """(mark cells, line) of each painted sheet row: a line whose first two cells are mark glyphs/spaces."""
            rows = []
            for line in self.body_text().splitlines():
                mark = line[:2].ljust(2)
                if any(ch not in MARKS + " " for ch in mark):
                    continue
                token = line[2:].split()[0] if line[2:].split() else ""
                if len(token) < 4 or token in ("Parameter",) or line.lstrip().startswith(("└", "new", "field", "text")):
                    continue
                rows.append((mark, line))
            return rows

        def row_index(self, needle: str) -> int:
            for i, (_, line) in enumerate(self.row_lines()):
                if needle in line:
                    return i
            return -1

        def selected_index(self) -> int:
            for i, (mark, _) in enumerate(self.row_lines()):
                if mark[0] == "▶":
                    return i
            return -1

        async def select(self, needle: str) -> None:
            if getattr(self.focused, "id", None) == "patch_sheet_input":
                await self.press("escape")
            for _ in range(80):
                target = self.row_index(needle)
                if target < 0:
                    raise AssertionError(f"row {needle!r} is not painted: {self.body_text()[:600]}")
                cur = self.selected_index()
                if cur == target:
                    return
                await self.press("down" if cur < target else "up", pause=0.15)
            raise AssertionError(f"could not select {needle!r}")

        async def begin_edit(self, needle: str) -> None:
            await self.select(needle)
            await self.press("enter")
            if getattr(self.focused, "id", None) != "patch_sheet_input":
                raise AssertionError(f"Enter did not focus the formula input (focus {self.focused})")

        async def type_text(self, text: str) -> None:
            for ch in text:
                await self.press(ch, pause=0.05)
            await self.settle(0.3)

        async def stage(self, needle: str, text: str) -> None:
            await self.begin_edit(needle)
            await self.type_text(text)
            await self.press("enter", pause=0.4)

        async def open_sheet(self, filter_text: str, present: str) -> None:
            self.panel().query_one("#patch_param_filter", Input).focus()
            await self.settle(0.3)
            await self.type_text(filter_text)
            if not await self._wait(lambda: self.row_index(present) >= 0, 20.0):
                raise AssertionError(f"page of filter {filter_text!r} never painted {present!r}")
            await self.settle(0.4)
            for _ in range(30):
                if getattr(self.focused, "id", None) == "patch_sheet_body":
                    return
                await self.press("tab", pause=0.2)
            raise AssertionError("Tab never reached the sheet body")

        def set_input(self, text: str) -> None:
            self.panel().query_one("#patch_sheet_input", Input).value = text

        # ---- the drive ------------------------------------------------ #

        async def _drive(self) -> None:
            try:
                await asyncio.sleep(0.5)
                self.load_a2l_from_path(a2l_path)
                if not await self._wait(lambda: bool(self._compute_a2l_enriched_tags()), 60.0):
                    raise TimeoutError("a2l load")
                await asyncio.sleep(0.5)
                self.load_from_path(s19_path)
                if not await self._wait(lambda: self.current_file is not None, 30.0):
                    raise TimeoutError("image load")
                await asyncio.sleep(0.5)
                self.action_show_screen("patch")
                await asyncio.sleep(1.2)
                lines.append(f"app_size={self.size.width}x{self.size.height}")
                await getattr(self, "sc_" + scen.replace("-", "_"))()
                await asyncio.sleep(0.6)
                lines.append(f"top_screen={type(self.screen).__name__}")
                lines.append(f"focused={getattr(self.focused, 'id', None) or type(self.focused).__name__}")
                lines.append(f"status_lines_this_run={len(statuses)}")
                for s in statuses[-6:]:
                    lines.append(f"status: {s}")
                try:
                    entries = len(self._change_service.document.entries)
                    lines.append(f"ledger_entries={entries}")
                except Exception:  # noqa: BLE001
                    pass
                if scen not in ("help", "help-use"):
                    lines.append("selected_rows=" + " | ".join(
                        f"[{m}] {ln[2:70].rstrip()}" for m, ln in self.row_lines() if m.strip()))
                    lines.append("sheet_text_begin")
                    lines.extend("  " + ln for ln in self.sheet_text().splitlines())
                    lines.append("sheet_text_end")
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

        # ---- scenarios ------------------------------------------------ #

        async def sc_layout(self):  # V-1, V-2: the filter row and the whole layout, filter `_0001`, sheet focused
            await self.open_sheet("_0001", "DISPLAY_0001")

        async def sc_rows(self):  # V-3: staged rows with real values and the Δ text
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.stage("DISPLAY_0001", "25.5")
            await self.select("ENUM_0001")
            await self.press("right")
            await self.press("enter")
            await self.press("enter", pause=0.4)
            await self.select("DISPLAY_0001")

        async def sc_p046(self):  # P-046: a selected pending row next to a staged row
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.stage("DISPLAY_0001", "25.5")
            await self.begin_edit("MASK_BIT_0001")
            await self.type_text("0")

        async def sc_number(self):  # V-4: number detail and formula bar, in limits
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.begin_edit("DISPLAY_0001")
            await self.type_text("25.5")

        async def sc_notice(self):  # V-4: `▲ <notice>` (outside limits, inside the extended limits)
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.begin_edit("DISPLAY_0001")
            await self.type_text("175")

        async def sc_longmsg(self):  # V-4: `✗ <message>` cut with `…` (300 x typed as one paste-sized value)
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.begin_edit("DISPLAY_0001")
            self.set_input("x" * 300)
            await self.settle(0.6)

        async def sc_enum(self):  # V-5 / V-6: enum widget, ENUM_0001
            await self.open_sheet("_0001", "ENUM_0001")
            await self.begin_edit("ENUM_0001")
            await self.press("right")

        async def sc_mask(self):  # V-7: the masked pair, both staged in one word
            await self.open_sheet("MASK", "MASK_FIELD_0001")
            await self.stage("MASK_FIELD_0001", "255")
            await self.stage("MASK_BIT_0001", "0")
            await self.begin_edit("MASK_FIELD_0001")

        async def sc_text(self):  # V-8: text widget
            await self.open_sheet("ASCII", "ASAM.C.ASCII")
            await self.begin_edit("ASAM.C.ASCII")
            self.set_input("ABC")
            await self.settle(0.6)

        async def sc_curve(self):  # V-9: curve row, no editor
            await self.open_sheet("CURVE.COM_AXIS", "ASAM.C.CURVE.COM")
            await self.select("ASAM.C.CURVE.COM")

        async def sc_array(self):  # V-9: array row, no editor
            await self.open_sheet("ARRAY.SWORD", "ASAM.C.ARRAY")
            await self.select("ASAM.C.ARRAY")

        async def sc_refused(self):  # V-9: a refused row
            await self.open_sheet("C.SCALAR.SWORD.FORM_X_PLUS_4", "ASAM.C.SCALAR")
            await self.select("refused")

        async def sc_bigtext(self):  # V-9: a text object over 4,096 bytes has no editor
            await self.open_sheet("ASCII", "ASAM.C.ASCII")
            await self.select("ASAM.C.ASCII")

        async def sc_status_staged(self):  # V-11: `staged as …`
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.stage("DISPLAY_0001", "25.5")

        async def sc_status_notice(self):  # V-11: the notice line after a stage that gave a notice
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.stage("DISPLAY_0001", "175")

        async def sc_status_overlap(self):  # V-11: `overlaps the entry at …`
            await self.open_sheet("_0001", "DISPLAY_0001")
            self._change_service.add_entry("0x800021", "", "11")
            lines.append("seeded: a raw bytes entry at 0x800021 (1 B) added through the app's ChangeService.add_entry")
            await self.stage("DISPLAY_0001", "25.5")

        async def sc_narrow(self):  # V-10: < 100 cells, sheet focused, nothing typed
            await self.open_sheet("_0001", "DISPLAY_0001")

        async def sc_narrow_edit(self):  # V-10: < 100 cells, editing a number row
            await self.open_sheet("_0001", "DISPLAY_0001")
            await self.begin_edit("DISPLAY_0001")
            await self.type_text("25.5")

        async def sc_help_use(self):  # V-12: the same window scrolled down to the `Use parameter` line
            await self.sc_help()
            for _ in range(1):
                await self.press("pagedown", pause=0.4)
            from textual.containers import VerticalScroll
            scrolls = list(self.screen.query(VerticalScroll))
            lines.append("help scroll_y=" + ",".join(f"{w.id}:{w.scroll_y}/{w.max_scroll_y}" for w in scrolls))

        async def sc_help(self):  # V-12: the Patch Editor help window
            chip = self.query_one("#window_help_patch")
            chip.press()
            if not await self._wait(lambda: bool(list(self.screen.query("#window_help_body"))), 10.0):
                raise AssertionError("help modal did not open")
            await self.settle(0.6)
            for sel in ("#window_help_body", "#window_help_keys"):
                found = list(self.screen.query(sel))
                if found:
                    r = found[0].render()
                    lines.append(f"help {sel}:")
                    lines.extend("  " + ln for ln in (getattr(r, "plain", None) or str(r)).splitlines())

        async def sc_k1(self):  # K-1: the key bar while the filter input has focus
            self.panel().query_one("#patch_param_filter", Input).focus()
            await self.settle(0.5)
            kb = self.query_one("#key_bar")
            for row in ("#key_bar_global", "#key_bar_window"):
                found = list(kb.query(row))
                if found:
                    r = found[0].render()
                    lines.append(f"key bar {row}: " + (getattr(r, "plain", None) or str(r)).replace("\n", " / "))

        # ---- F8 (F-I10-1): the Inspector tab inside LANDS IN's 6 content rows ---- #

        def inspector_facts(self) -> None:
            """Painted LANDS IN rows, the pane's scroll, and the painted region and hit test of the entry controls."""
            from textual.errors import NoWidget

            pane = self.query_one("#patch_pane_inspector")
            lines.append(f"inspector_scroll_y={pane.scroll_y}/{pane.max_scroll_y}")
            for wid in ("patch_entry_address_input", "patch_entry_bytes_input", "patch_entry_add_button",
                        "patch_doc_path_input", "patch_doc_validate_button"):
                widget = self.query_one(f"#{wid}")
                try:
                    seen = self.screen.find_widget(widget).visible_region
                except NoWidget:
                    seen = None
                hit = self.get_widget_at(*seen.center)[0] if seen is not None and seen.area else None
                lines.append(f"painted {wid}: {seen} hit_at_centre={getattr(hit, 'id', None)}")
            lands_in = self.query_one("#patch_inspector")
            strips = self.screen._compositor.render_strips()
            r = lands_in.region
            lines.append("lands_in_painted_begin")
            for y in range(r.y, r.y + r.height):
                lines.append("  " + "".join(s.text for s in strips[y].crop(r.x, r.x + r.width)).rstrip())
            lines.append("lands_in_painted_end")

        async def show_inspector(self) -> None:
            chip = self.panel().query_one("#patch_tab_inspector")
            chip.focus()
            await self.settle(0.3)
            await self.press("enter", pause=0.5)
            current = self.panel().query_one("#patch_tab_switcher").current
            if current != "patch_pane_inspector":
                raise AssertionError(f"enter on the Inspector chip showed {current}")

        async def sc_inspector(self):  # F8: the Inspector tab as it lands, pane at its top
            await self.show_inspector()
            self.inspector_facts()

        async def sc_inspector_add(self):  # F8: Tab from Address to Bytes, then to Add: focus scrolls the pane
            await self.show_inspector()
            self.panel().query_one("#patch_entry_address_input", Input).focus()
            await self.settle(0.3)
            await self.type_text("0x800021")
            await self.press("tab")
            await self.press("tab")
            await self.type_text("11")
            await self.press("tab", pause=0.5)
            self.inspector_facts()

    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
