"""Inc 8b capture driver (batch-103, CAP8b): the REAL app, isolated state, real keys. Adapted from capture_i9_driver.py.

Run by capture_8b.ps1 under ``python -I -B`` in a fresh Windows Terminal window. It drives the Patch Editor's
staging sheet to the state one scene asks for, through the app's own key handling (``App._press_keys``), then writes
a sidecar of the state actually reached (the whole painted screen) and reports ``surface=ready``.

Fixture (built once by build_fixtures_8b.py, never in the repo): grid8b = DEFC (tools/synth/make_release_case.py
--case definitions, seed 20260001) plus TEXT_0001 (ASCII, 42 B) and NAN_0001 (FLOAT32, image FF FF FF FF), so the
`_0001` page holds a number, enum, bit-mask, text, array and NaN row. The OS clipboard is never touched (stubbed).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

BODY, INPUT, SHEET = "#patch_sheet_body", "#patch_sheet_input", "#patch_sheet"
GRID_F = "grid8b"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--fixtures", required=True, type=Path)
    ap.add_argument("--base", required=True, type=Path)
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--release", type=Path, default=None)
    ap.add_argument("--size", default="")
    ap.add_argument("--commit", default="")
    args = ap.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))

    from textual.app import App
    from textual.widgets import Input

    import s19_app.tui.os_clipboard_input as oci
    from s19_app.tui import a2l_definition
    from s19_app.tui.app import S19TuiApp

    writes: list[int] = []
    oci.write_os_clipboard = lambda text: (writes.append(len(text)) or True)

    def mirror_only(self, text: str) -> None:
        self._clipboard = text

    App.copy_to_clipboard = mirror_only

    base = args.base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    fx = args.fixtures.resolve()
    scen = args.scenario
    keys_log: list[str] = []
    statuses: list[str] = []
    lines: list[str] = []

    def release_set() -> bool:
        return args.release is not None and args.release.exists()

    scrub_words = [os.environ.get("USERPROFILE", ""), str(base), str(fx), str(root)]

    def scrub(text: str) -> str:
        for w in scrub_words:
            if w:
                text = text.replace(w, "<user>").replace(w.replace("\\", "/"), "<user>")
        return text.replace(os.environ.get("USERNAME", "<user>"), "<user>")  # account name read at run time (PP-03)

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

        # ---- helpers ----
        async def _wait(self, pred, timeout=30.0) -> bool:
            end = time.perf_counter() + timeout
            while time.perf_counter() < end:
                if pred():
                    return True
                await asyncio.sleep(0.05)
            return False

        async def settle(self, seconds: float = 0.3) -> None:
            await asyncio.sleep(seconds)

        async def press(self, *keys: str, pause: float = 0.25) -> None:
            keys_log.append(" ".join(keys))
            await self._press_keys(keys)
            await asyncio.sleep(pause)

        def panel(self):
            return self.query_one("#patch_editor_panel")

        def sheet(self):
            return self.panel().query_one(SHEET)

        def names(self) -> list:
            return [r.name for r in self.sheet().rows]

        def st(self, name):
            return self.sheet().states.get(name)

        def screen_lines(self) -> list:
            strips = self.screen._compositor.render_strips()
            return [s.text.rstrip() for s in strips]

        def screen_text(self) -> str:
            return "\n".join(self.screen_lines())

        def set_input(self, text: str) -> None:
            shown = text if len(text) <= 40 else text[:40] + f"...({len(text)} chars)"
            keys_log.append(f"<set op input to {shown!r}>")
            self.sheet().query_one(INPUT, Input).value = text

        async def open_sheet(self, filter_text: str, present: str, to_body: bool = True) -> None:
            flt = self.panel().query_one("#patch_param_filter", Input)
            flt.focus()
            await self.settle(0.3)
            if filter_text:
                keys_log.append(f"<type filter {filter_text!r}>")
                for ch in filter_text:
                    await self._press_keys((ch,))
                    await asyncio.sleep(0.05)
            if not await self._wait(lambda: present in self.names(), 30.0):
                raise AssertionError(f"filter {filter_text!r} never painted {present!r}: {self.names()}")
            await self.settle(0.5)
            if not to_body:
                return
            for _ in range(30):
                if getattr(self.focused, "id", None) == "patch_sheet_body":
                    return
                await self.press("tab", pause=0.2)
            raise AssertionError("Tab never reached the sheet body")

        async def pick(self, name: str) -> None:
            sh = self.sheet()
            cur = self.st(sh.selected_name) if sh.selected_name else None
            if cur is not None and cur.focus:
                await self.press("escape")
            elif getattr(self.focused, "id", None) == "patch_sheet_input":
                await self.press("escape")
            if getattr(self.focused, "id", None) != "patch_sheet_body":
                sh.query_one(BODY).focus()
                await self.settle(0.2)
            names = self.names()
            if name not in names:
                raise AssertionError(f"{name} not on the page {names}")
            for _ in range(len(names) + 3):
                if sh.selected_name == name:
                    return
                await self.press("down" if names.index(name) > names.index(sh.selected_name) else "up", pause=0.2)
            raise AssertionError(f"could not select {name}")

        def has_values(self, name) -> bool:
            s = self.st(name)
            return s is not None and s.values is not None

        async def open_bench(self, name: str, decoded: bool = True, timeout: float = 120.0) -> None:
            await self.pick(name)
            await self._wait(lambda: self.st(name) is not None, 10)
            if not self.st(name).focus:
                await self.press("enter")
            if not self.st(name).focus:
                raise AssertionError(f"Enter did not give the bench of {name} the focus")
            if decoded and not await self._wait(lambda: self.has_values(name), timeout):
                raise AssertionError(f"values of {name} never arrived")
            await self.settle(0.3)

        async def apply(self, key: str, operand: str, back: bool = True, wait_preview: bool = True) -> None:
            await self.press(key, "enter")
            if getattr(self.focused, "id", None) != "patch_sheet_input":
                raise AssertionError("Enter did not reach the op input")
            self.set_input(operand)
            await self.settle(0.3)
            await self.press("enter")
            if wait_preview:
                await self._wait(lambda: any(t in self.screen_text() for t in ("differ", "refused", "no edit yet")), 20)
            await self.settle(0.4)
            if back:
                await self.press("escape")
            await self.settle(0.3)

        async def alt_s(self) -> None:
            await self.press("alt+s", pause=0.6)

        # ---- the drive ----
        async def _drive(self) -> None:
            try:
                fixture, filt, present, func, to_body = SCENES[scen]
                a2l_path, s19_path = fx / (fixture + ".a2l"), fx / (fixture + ".s19")
                lines.extend([f"scene={scen}", f"fixture={fixture}", "os_clipboard=stubbed (never touched)",
                              f"commit={args.commit}", f"requested_size={args.size}",
                              f"time={time.strftime('%Y-%m-%d %H:%M:%S')}"])
                await asyncio.sleep(0.5)
                self.load_a2l_from_path(a2l_path)
                if not await self._wait(lambda: bool(self._compute_a2l_enriched_tags()), 90.0):
                    raise TimeoutError("a2l load")
                await asyncio.sleep(0.5)
                self.load_from_path(s19_path)
                if not await self._wait(lambda: self.current_file is not None, 60.0):
                    raise TimeoutError("image load")
                await asyncio.sleep(0.5)
                self.action_show_screen("patch")
                await asyncio.sleep(1.2)
                lines.append(f"app_size={self.size.width}x{self.size.height}")
                await self.open_sheet(filt, present, to_body)
                await func(self)
                await asyncio.sleep(0.8)
                lines.append(f"focused={getattr(self.focused, 'id', None) or type(self.focused).__name__}")
                sel = self.sheet().selected_name
                lines.append(f"selected={sel}")
                s = self.st(sel) if sel else None
                if s is not None:
                    lines.append(f"bench_state: cursor={s.cursor} anchor={s.anchor} tool={s.tool} focus={s.focus} edit={dict(s.edit)} undo={len(s.undo)}")
                lines.append("page_rows=" + ", ".join(self.names()))
                try:
                    b = self.query_one("#patch_sheet_body")
                    lines.append(f"body: size={b.size.width}x{b.size.height} content_size={b.content_size.width}x{b.content_size.height} sheet_top={self.sheet().top}")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"body: n/a ({type(exc).__name__})")
                try:
                    g = self.query_one("#patch_sheet_grid")
                    lines.append(f"grid: scroll_x={g.scroll_x} size={g.size.width}x{g.size.height} virtual_size={g.virtual_size.width}x{g.virtual_size.height} max_scroll_x={g.max_scroll_x} show_horizontal_scrollbar={g.show_horizontal_scrollbar}")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"grid: n/a ({type(exc).__name__})")
                lines.append(f"subtitle={getattr(self.sheet(), 'border_subtitle', None)!r}")
                for wid in ("patch_sheet", "patch_inspector", "patch_editor_panel"):
                    try:
                        w = self.query_one("#" + wid)
                        lines.append(f"widget #{wid}: size={w.size.width}x{w.size.height} classes={sorted(w.classes)} subtitle={getattr(w, 'border_subtitle', None)!r}")
                    except Exception as exc:  # noqa: BLE001
                        lines.append(f"widget #{wid}: n/a ({type(exc).__name__})")
                lines.append("keys_sent: " + " | ".join(keys_log))
                lines.append(f"status_lines_this_run={len(statuses)}")
                for t in statuses[-8:]:
                    lines.append(f"status: {scrub(t)}")
                lines.append(f"stub_os_writes={len(writes)}")
                lines.append("screen_text_begin")
                lines.extend("  " + scrub(ln) for ln in self.screen_lines())
                lines.append("screen_text_end")
                lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001
                import traceback
                lines.append(f"surface=error {type(exc).__name__}: {scrub(str(exc))}")
                lines.extend("  " + scrub(ln) for ln in traceback.format_exc().splitlines()[-10:])
                try:
                    lines.append("keys_sent: " + " | ".join(keys_log))
                    lines.append("screen_text_begin")
                    lines.extend("  " + scrub(ln) for ln in self.screen_lines())
                    lines.append("screen_text_end")
                except Exception:  # noqa: BLE001
                    pass
            finally:
                if args.report is not None:
                    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
                if args.release is not None:
                    await self._wait(lambda: args.release.exists(), 180.0)
                self.exit(0)

    # ---- scenes ---- (each is `async def f(a)`; the page is the `_0001` filter of the grid8b fixture) ----
    MAP, DISP, ENUM = "MAP_DEF_0001", "DISPLAY_0001", "ENUM_0001"

    async def decoded_arrays(a):  # the array rows' summary strips need their values: select each once, then leave
        for n in ("MAP_DEF_0001",):
            await a.pick(n)
            await a._wait(lambda n=n: a.has_values(n), 60)
        await a.settle(0.5)

    async def s_grid(a):  # every row kind at once; DISPLAY_0001 selected (one expanded line)
        await decoded_arrays(a)
        await a.pick(DISP)
        await a.settle(0.6)

    async def s_end(a):
        await s_grid(a)
        await a.press("end", pause=0.6)

    async def s_home(a):
        await s_grid(a)
        await a.press("end", pause=0.6)
        await a.press("home", pause=0.6)

    async def s_enum(a):
        await decoded_arrays(a)
        await a.pick(ENUM)
        await a.settle(0.6)

    async def s_bit(a):
        await decoded_arrays(a)
        await a.pick("MASK_FIELD_0001")
        await a.settle(0.6)

    async def s_text(a):
        await decoded_arrays(a)
        await a.pick("TEXT_0001")
        await a.settle(0.6)

    async def s_expanded(a):  # an expanded object (MASK_BIT_0001, as the approved D.off.sheet) between its neighbours
        await decoded_arrays(a)
        await a.pick("MASK_BIT_0001")
        await a.settle(0.6)

    async def s_filter(a):  # the picker row with the include chip, focus left in the filter
        await a.settle(0.6)

    async def s_array(a):
        await decoded_arrays(a)
        await a.pick(MAP)
        await a.settle(0.6)

    async def s_nan(a):
        await decoded_arrays(a)
        await a.pick("NAN_0001")
        await a.settle(0.6)

    G = GRID_F
    SCENES = {
        "grid": (G, "_0001", DISP, s_grid, True), "end": (G, "_0001", DISP, s_end, True),
        "home": (G, "_0001", DISP, s_home, True), "enum": (G, "_0001", DISP, s_enum, True),
        "bit": (G, "_0001", DISP, s_bit, True), "text": (G, "_0001", DISP, s_text, True),
        "expanded": (G, "_0001", DISP, s_expanded, True), "filter": (G, "_0001", DISP, s_filter, False),
        "array": (G, "_0001", DISP, s_array, True), "nan": (G, "_0001", DISP, s_nan, True),
    }
    if scen not in SCENES:
        print("unknown scene", scen, sorted(SCENES))
        return 2
    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
