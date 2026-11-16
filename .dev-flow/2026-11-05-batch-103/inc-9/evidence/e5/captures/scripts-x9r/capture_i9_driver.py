"""Inc 9 capture driver (batch-103, X9): the REAL app, isolated state, real keys. Adapted from capture_i8_driver.py.

Run by capture_i9.ps1 under ``python -I -B`` in a fresh Windows Terminal window. It drives the Patch Editor's
staging sheet / bench to the state one scene asks for, through the app's own key handling (``App._press_keys``),
then writes a sidecar of the state actually reached (the whole painted screen) and reports ``surface=ready``.

Fixtures (built once by build_fixtures_i9.py, never in the repo): defc (tools/synth/make_release_case.py --case
definitions, seed 20260001), hand (VB1D, TAB_VB, F32_BLK, REF_BLK image missing its last byte, NTC_BLK), large (LARGE
UBYTE x 1,048,576 + SMALL_BLK). The OS clipboard is never touched (stubbed). Scenes that need "while decoding /
encoding" install a transparent wait around I-2's decode_values / encode_values (same results, only delayed until the
launcher has taken its PNG): that is the only product-side interposition.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

BODY, INPUT, SHEET = "#patch_sheet_body", "#patch_sheet_input", "#patch_sheet"
DEFC_F, HAND_F, LARGE_F = "defc", "hand", "large"


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
    holds = {"decode": None, "encode": None}  # None | set of names | "*"

    def release_set() -> bool:
        return args.release is not None and args.release.exists()

    def install_hold(function: str, kind: str) -> None:
        original = getattr(a2l_definition, function)

        def wrapper(definition, *a, **kw):
            target = holds[kind]
            if target and (target == "*" or definition.name in target):
                end = time.monotonic() + 120
                while not release_set() and time.monotonic() < end:
                    time.sleep(0.1)
            return original(definition, *a, **kw)

        for module in list(sys.modules.values()):
            if str(getattr(module, "__name__", "")).startswith("s19_app") and getattr(module, function, None) is original:
                setattr(module, function, wrapper)

    install_hold("decode_values", "decode")
    install_hold("encode_values", "encode")

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

        async def open_sheet(self, filter_text: str, present: str) -> None:
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
                fixture, filt, present, func = SCENES[scen]
                if fixture == DEFC_F:
                    a2l_path, s19_path = fx / "defc" / "definitions.a2l", fx / "defc" / "definitions.s19"
                else:
                    a2l_path, s19_path = fx / (fixture + ".a2l"), fx / (fixture + ".s19")
                lines.extend([f"scene={scen}", f"fixture={fixture}", "os_clipboard=stubbed (never touched)",
                              f"commit={args.commit}", f"requested_size={args.size}",
                              f"time={time.strftime('%Y-%m-%d %H:%M:%S')}"])
                if scen in HOLD_DECODE:
                    holds["decode"] = HOLD_DECODE[scen]
                    lines.append(f"interposition: decode_values waits for the PNG ({HOLD_DECODE[scen]})")
                if scen in HOLD_ENCODE:
                    holds["encode"] = HOLD_ENCODE[scen]
                    lines.append(f"interposition: encode_values waits for the PNG ({HOLD_ENCODE[scen]})")
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
                await self.open_sheet(filt, present)
                await func(self)
                await asyncio.sleep(0.8)
                lines.append(f"focused={getattr(self.focused, 'id', None) or type(self.focused).__name__}")
                sel = self.sheet().selected_name
                lines.append(f"selected={sel}")
                s = self.st(sel) if sel else None
                if s is not None:
                    lines.append(f"bench_state: cursor={s.cursor} anchor={s.anchor} tool={s.tool} focus={s.focus} edit={dict(s.edit)} undo={len(s.undo)}")
                lines.append("page_rows=" + ", ".join(self.names()))
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

    # ---- scenes ---- (each is `async def f(a)`) ----
    MAP, CURVE, VB = "MAP_DEF_0001", "CURVE_DEF_0001", "VAL_BLK_DEF_0001"

    async def s_v1(a):  # V-1: a bench row selected (no Enter)
        await a.pick(VB)
        await a._wait(lambda: a.has_values(VB), 60)
        await a.settle(0.5)

    async def s_i8v13(a):
        await a.pick(MAP)
        await a._wait(lambda: a.has_values(MAP), 60)
        await a.settle(0.5)

    async def s_v2(a):  # V-2: pending (MAP) + staged (VB) rows, selection moved to DISPLAY_0001 (no bench: the rows stay in view)
        await a.open_bench(VB)
        await a.apply("d", "1")
        await a.alt_s()
        await a.open_bench(MAP)
        await a.apply("s", "5")
        await a.pick("DISPLAY_0001")
        await a.settle(0.8)

    async def s_v2_summary(a):  # V-2: rows not yet summarised (decode held): `... <count>`
        await a.settle(1.0)

    async def s_v2_large(a):  # V-2: `<n> values` for LARGE (not decoded) beside SMALL_BLK
        await a.pick("SMALL_BLK")
        await a._wait(lambda: a.has_values("SMALL_BLK"), 60)
        await a.settle(0.6)

    async def s_v3(a):  # V-3: curve chart, two points selected, +delta 5 applied
        await a.open_bench(CURVE)
        await a.press("shift+right", "shift+right")
        await a.apply("d", "5")

    async def s_v4(a):  # V-4: map grid, 2x2 block, +delta 10
        await a.open_bench(MAP)
        await a.press("shift+right", "shift+down")
        await a.apply("d", "10")

    async def s_v5a(a):  # V-5: 1-D VAL_BLK (40 elements, 16 columns)
        await a.open_bench("VB1D")
        await a.press("shift+right", "shift+right", "shift+right")
        await a.apply("d", "3")

    async def s_v5b(a):  # V-5: 2-D VAL_BLK (MATRIX_DIM 3 2)
        await a.open_bench(VB)
        await a.press("shift+right", "shift+down")
        await a.apply("d", "2")

    async def s_v6_decoding(a):  # V-6: LARGE while its decode is held
        await a.open_bench("LARGE", decoded=False)
        await a.settle(0.8)

    async def s_v6_window(a):  # V-6: LARGE decoded, window line
        await a.open_bench("LARGE", decoded=True, timeout=150)

    async def s_v6_paged(a):  # V-6: after paging
        await a.open_bench("LARGE", decoded=True, timeout=150)
        await a.press("pagedown", pause=0.6)
        await a.press("pagedown", pause=0.6)
        await a.press("shift+down", "shift+down", "shift+down")

    async def s_v7_focus(a):  # V-7: cursor, selection, bench focus
        await a.open_bench(MAP)
        await a.press("shift+right", "shift+down")

    async def s_v7_escape(a):  # V-7: after Escape back
        await a.open_bench(MAP)
        await a.press("shift+right", "shift+down")
        await a.press("escape")

    async def s_v7_nofocus(a):  # V-7: row selected, bench not focused (no marker)
        await a.pick(MAP)
        await a._wait(lambda: a.has_values(MAP), 60)
        await a.settle(0.5)

    async def s_v8_interp(a):  # V-8: Interpolate over 1 row x 4 columns of the map
        await a.open_bench(MAP)
        await a.press("shift+right", "shift+right", "shift+right")
        await a.apply("i", "")

    async def s_v8_smooth(a):  # V-8: Smooth over 6 elements of VB1D
        await a.open_bench("VB1D")
        await a.press("shift+right", "shift+right", "shift+right", "shift+right", "shift+right")
        await a.apply("m", "")

    async def s_v9_ok(a):
        await a.open_bench(MAP)
        await a.press("shift+right")
        await a.apply("d", "1")

    async def s_v9_notice(a):  # notice: NTC_BLK limits 0..100, extended 0..200, Set 150
        await a.open_bench("NTC_BLK")
        await a.apply("s", "150")

    async def s_v9_refused(a):
        await a.open_bench(VB)
        await a.apply("s", "abc")

    async def s_v9_cut(a):  # a 300-character refused operand: the op line cut at the bar edge
        await a.open_bench(VB)
        await a.apply("s", "x" * 300)

    async def s_v10_encoding(a):  # `encoding ...` (encode held)
        await a.open_bench(MAP)
        await a.press("d", "enter")
        a.set_input("1")
        await a.settle(0.3)
        await a.press("enter")
        await a.settle(1.0)

    async def s_v10_cut(a):  # many runs of changed bytes: the bytes line cut
        await a.open_bench("VB1D")
        await a.press(*(["shift+right"] * 15))
        await a.apply("d", "3")

    async def s_v12_staged(a):
        await a.open_bench(VB)
        await a.press("shift+right")
        await a.apply("d", "1")
        await a.alt_s()

    async def s_v12_notice(a):
        await a.open_bench("NTC_BLK")
        await a.apply("s", "150")
        await a.alt_s()

    async def s_v12_refused(a):
        await a.open_bench(VB)
        await a.apply("s", "abc")
        await a.alt_s()

    async def s_v12_empty(a):
        await a.open_bench(MAP)
        await a.alt_s()

    async def s_v13_decoding(a):  # apply and stage while decoding (decode held)
        await a.open_bench("LARGE", decoded=False)
        await a.apply("d", "1", wait_preview=False)
        await a.press("alt+s", pause=0.5)

    async def s_v13_undo(a):
        await a.open_bench(MAP)
        await a.press("u", pause=0.5)

    async def s_v13_nan(a):
        await a.open_bench(MAP)
        await a.apply("d", "abc", wait_preview=False)

    async def s_v13_texts(a):
        await a.open_bench("TAB_VB")
        await a.apply("d", "1", wait_preview=False)

    async def s_v13_novalue(a):
        await a.open_bench("F32_BLK")
        await a.press("shift+right")
        await a.apply("d", "1", wait_preview=False)

    async def s_v13_columns(a):
        await a.open_bench(MAP)
        await a.apply("i", "", wait_preview=False)

    async def s_v13_columns_smooth(a):
        await a.open_bench(MAP)
        await a.press("shift+right")
        await a.apply("m", "", wait_preview=False)

    async def s_v14_map(a):
        await a.open_bench(MAP)
        await a.press("shift+right", "shift+down")

    async def s_v14_large(a):
        await a.open_bench("LARGE", decoded=True, timeout=150)

    async def s_refused_decode(a):  # R-PE-BENCH.14, W-8: REF_BLK, the image misses the last byte
        await a.pick("REF_BLK")
        await a.settle(2.0)
        await a.press("enter", pause=1.5)

    async def s_refused_row(a):  # the row (Current cell) only
        await a.pick("REF_BLK")
        await a.settle(2.0)

    async def s_v2_vb1d(a):  # X9r V-2 (F-X9-5): VB1D (40 elements, 16 columns) summarised, another row selected
        await a.pick("NTC_BLK")
        await a._wait(lambda: a.st("VB1D") is not None and a.st("VB1D").strip is not None, 60)
        await a.settle(0.8)

    async def s_ob_json(a):  # X9r O-B: a staged record, the JSON tab, the cursor on an opening bracket of the view
        from textual.widgets import TextArea
        await a.open_bench(VB)
        await a.press("shift+right")
        await a.apply("d", "1")
        await a.alt_s()
        await a.press("escape")
        chip = a.panel().query_one("#patch_tab_json")
        keys_log.append("<focus #patch_tab_json>")
        chip.focus()
        await a.settle(0.3)
        await a.press("enter", pause=0.6)
        view = a.panel().query_one("#patch_json_view", TextArea)
        keys_log.append("<focus #patch_json_view>")
        view.focus()
        await a.settle(0.3)
        doc = view.text.split("\n")
        # The opening bracket whose match is nearest (same line first), so both ends fit the 3-line view.
        best = None
        for r, line in enumerate(doc):
            for c, ch in enumerate(line):
                if ch not in "[{":
                    continue
                depth, end = 0, None
                for r2 in range(r, len(doc)):
                    for c2, ch2 in enumerate(doc[r2]):
                        if (r2, c2) < (r, c):
                            continue
                        depth += ch2 in "[{"
                        depth -= ch2 in "]}"
                        if depth == 0:
                            end = (r2, c2)
                            break
                    if end:
                        break
                if end and end != (r, c) and (best is None or end[0] - r < best[0]):
                    best = (end[0] - r, (r, c), end)
        if best is None:
            raise AssertionError("no opening bracket with a match in the JSON view")
        target = best[1]
        lines.append(f"json_view_target={target} its_match={best[2]} (the nearest pair)")
        row0 = view.cursor_location[0]
        if row0 > target[0]:
            await a.press(*(["up"] * (row0 - target[0])), pause=0.2)
        elif row0 < target[0]:
            await a.press(*(["down"] * (target[0] - row0)), pause=0.2)
        await a.press("home", pause=0.2)
        row, col = view.cursor_location
        if col > target[1]:
            await a.press(*(["left"] * (col - target[1])), pause=0.2)
        elif col < target[1]:
            await a.press(*(["right"] * (target[1] - col)), pause=0.2)
        await a.settle(0.6)
        # The view is 3 lines tall: scroll (the cursor stays put) so the matching end is on screen, where Textual
        # paints the bracket-match highlight when a match was found.
        y = max(0, best[2][0] - (view.content_size.height - 1))
        keys_log.append(f"<scroll #patch_json_view to y={y}; the cursor stays>")
        view.scroll_to(y=y, animate=False)
        await a.settle(0.6)
        lines.append(f"json_view_scroll_y={view.scroll_y} height={view.content_size.height}")
        loc = view.cursor_location
        lines.append(f"json_view_class={type(view).__name__} read_only={view.read_only} lines={len(doc)}")
        lines.append(f"json_view_cursor={loc} char={doc[loc[0]][loc[1]]!r} target={target}")
        lines.append(f"json_view_matching_bracket_location={getattr(view, '_matching_bracket_location', 'n/a')}")
        lines.append(f"json_view_textual_match_would_be={TextArea.find_matching_bracket(view, doc[loc[0]][loc[1]], loc)}")

    HOLD_DECODE = {"v2-summary": "*", "v6-decoding": {"LARGE"}, "v13-decoding": {"LARGE"}}
    HOLD_ENCODE = {"v10-encoding": "*"}
    D, H, L = DEFC_F, HAND_F, LARGE_F
    SCENES = {
        "i8v13": (D, "_0001", MAP, s_i8v13), "v1": (D, "_0001", VB, s_v1), "v2": (D, "_0001", VB, s_v2),
        "v2-summary": (D, "_0001", VB, s_v2_summary), "v2-large": (L, "", "LARGE", s_v2_large),
        "v3": (D, "_0001", CURVE, s_v3), "v4": (D, "_0001", MAP, s_v4), "v5a": (H, "VB1D", "VB1D", s_v5a),
        "v5b": (D, "_0001", VB, s_v5b), "v6-decoding": (L, "LARGE", "LARGE", s_v6_decoding),
        "v6-window": (L, "LARGE", "LARGE", s_v6_window), "v6-paged": (L, "LARGE", "LARGE", s_v6_paged),
        "v7-focus": (D, "_0001", MAP, s_v7_focus), "v7-escape": (D, "_0001", MAP, s_v7_escape),
        "v7-nofocus": (D, "_0001", MAP, s_v7_nofocus), "v8-interp": (D, "_0001", MAP, s_v8_interp),
        "v8-smooth": (H, "VB1D", "VB1D", s_v8_smooth), "v9-ok": (D, "_0001", MAP, s_v9_ok),
        "v9-notice": (H, "NTC_BLK", "NTC_BLK", s_v9_notice), "v9-refused": (D, "_0001", VB, s_v9_refused),
        "v9-cut": (D, "_0001", VB, s_v9_cut), "v10-encoding": (D, "_0001", MAP, s_v10_encoding),
        "v10-cut": (H, "VB1D", "VB1D", s_v10_cut), "v12-staged": (D, "_0001", VB, s_v12_staged),
        "v12-notice": (H, "NTC_BLK", "NTC_BLK", s_v12_notice), "v12-refused": (D, "_0001", VB, s_v12_refused),
        "v12-empty": (D, "_0001", MAP, s_v12_empty), "v13-decoding": (L, "LARGE", "LARGE", s_v13_decoding),
        "v13-undo": (D, "_0001", MAP, s_v13_undo), "v13-nan": (D, "_0001", MAP, s_v13_nan),
        "v13-texts": (H, "TAB_VB", "TAB_VB", s_v13_texts), "v13-novalue": (H, "F32_BLK", "F32_BLK", s_v13_novalue),
        "v13-columns": (D, "_0001", MAP, s_v13_columns), "v13-columns-smooth": (D, "_0001", MAP, s_v13_columns_smooth),
        "v14-map": (D, "_0001", MAP, s_v14_map), "v14-large": (L, "LARGE", "LARGE", s_v14_large),
        "x-refused-decode": (H, "REF_BLK", "REF_BLK", s_refused_decode), "x-refused-row": (H, "", "REF_BLK", s_refused_row),
        "v2-vb1d": (H, "", "VB1D", s_v2_vb1d), "ob-json": (D, "_0001", VB, s_ob_json),
    }
    if scen not in SCENES:
        print("unknown scene", scen, sorted(SCENES))
        return 2
    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
