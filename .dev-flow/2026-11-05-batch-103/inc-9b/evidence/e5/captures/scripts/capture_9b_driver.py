"""CAP9b real-application driver with painted-state capture/acknowledgement gates.

Adapted from capture_i9_driver.py, with the Inc 8b geometry diagnostics. The
launcher owns PNG writing; this driver owns I-2/timer interposition and writes
one atomic exact-state report per requested PNG. The final release flag is only
for application close, never for releasing a busy job.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

BODY, INPUT, SHEET = "#patch_sheet_body", "#patch_sheet_input", "#patch_sheet"
WIN = "#patch_sheet_win"
VB, LARGE, SMALL = "VAL_BLK_DEF_0001", "LARGE", "SMALL_BLK"
FRAMES = "◐◓◑◒"
PILL = re.compile(r"([◐◓◑◒]) BUSY · (stage|decode|preview) (.*?) · (\d+\.\d) s · keys still work ")
JOB_SCENES = {"decode", "preview", "stage-encode", "stage-refresh", "stage-refused"}
NAME_SCENES = {
    "name-markup": "[@click=app.quit]X[/]",
    "name-brackets": "A[b]B",
    "name-esc": "A\x1b[2J",
    "name-c1": "B\x85C",
    "name-long": "N" * 300,
    "name-short": "N",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--fixtures", required=True, type=Path)
    ap.add_argument("--base", required=True, type=Path)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--release", required=True, type=Path)
    ap.add_argument("--ack", required=True, type=Path)
    ap.add_argument("--png-f1", required=True, type=Path)
    ap.add_argument("--size", required=True)
    ap.add_argument("--commit", required=True)
    args = ap.parse_args()
    if args.scenario not in JOB_SCENES | NAME_SCENES.keys():
        raise ValueError(f"unknown scene {args.scenario}")
    root = args.root.resolve()
    sys.path.insert(0, str(root))

    from textual.app import App
    from textual.widgets import DataTable, Input

    import s19_app.tui.os_clipboard_input as oci
    from s19_app.tui import a2l_definition
    from s19_app.tui.app import S19TuiApp
    from tests.b97_probes import painted_rows, painted_style

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
    holds = {"decode": set(), "encode": set()}
    gate_entered = {"decode": set(), "encode": set()}
    gate_release = {"decode": threading.Event(), "encode": threading.Event()}
    stage_counts = {"before": 0}
    refresh_state = {"held": 0, "invoked": 0}
    scrub_words = [os.environ.get("USERPROFILE", ""), str(base), str(fx), str(root)]

    def scrub(text: str) -> str:
        for word in scrub_words:
            if word:
                text = text.replace(word, "<scratch>").replace(word.replace("\\", "/"), "<scratch>")
        text = text.replace(os.environ.get("USERNAME", "<user>"), "<user>")
        return "".join(ch if ch == "\n" or ord(ch) >= 32 and not 127 <= ord(ch) <= 159 else "" for ch in text)

    def install_hold(function: str, kind: str) -> None:
        original = getattr(a2l_definition, function)

        def wrapper(definition, *a, **kw):
            if definition.name in holds[kind]:
                gate_entered[kind].add(definition.name)
                if not gate_release[kind].wait(120.0):
                    raise TimeoutError(f"CAP9b {kind} gate was not released")
            return original(definition, *a, **kw)

        for module in list(sys.modules.values()):
            if str(getattr(module, "__name__", "")).startswith("s19_app") and getattr(module, function, None) is original:
                setattr(module, function, wrapper)

    install_hold("decode_values", "decode")
    install_hold("encode_values", "encode")

    class CaptureApp(S19TuiApp):
        CSS_PATH = str(root / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)
            self.capture_seq = 0
            self.first_busy = None
            self.capture_error = None

        def set_status(self, message: str) -> None:
            statuses.append(message)
            super().set_status(message)

        def on_mount(self) -> None:
            super().on_mount()
            self._capture_task = asyncio.create_task(self._drive())

        async def _wait(self, predicate, timeout=30.0) -> bool:
            end = time.perf_counter() + timeout
            while time.perf_counter() < end:
                if predicate():
                    return True
                if args.release.exists():
                    raise TimeoutError("final close requested while waiting for capture state")
                await asyncio.sleep(0.02)
            return False

        async def press(self, *keys: str, pause: float = 0.05) -> None:
            keys_log.append(" ".join(keys) if len(keys) <= 20 else f"<{len(keys)} selection keys>")
            await self._press_keys(keys)
            if pause:
                await asyncio.sleep(pause)

        def panel(self):
            return self.query_one("#patch_editor_panel")

        def sheet(self):
            return self.panel().query_one(SHEET)

        def names(self) -> list:
            return [row.name for row in self.sheet().rows]

        def st(self, name):
            return self.sheet().states.get(name)

        def has_values(self, name) -> bool:
            state = self.st(name)
            return state is not None and state.values is not None

        def previewed(self, name) -> bool:
            state = self.st(name)
            return state is not None and state.preview is not None and not isinstance(state.preview, str)

        def entries(self):
            return list(self._change_service.document.entries)

        async def open_sheet(self, filter_text: str, present: str) -> None:
            filter_widget = self.panel().query_one("#patch_param_filter", Input)
            filter_widget.focus()
            await asyncio.sleep(0.1)
            if filter_text:
                keys_log.append(f"<type filter {filter_text!r}>")
                for char in filter_text:
                    await self._press_keys((char,))
            if not await self._wait(lambda: present in self.names(), 30.0):
                raise AssertionError(f"filter did not paint {present!r}")
            for _ in range(30):
                if getattr(self.focused, "id", None) == "patch_sheet_body":
                    return
                await self.press("tab")
            raise AssertionError("Tab never reached the sheet body")

        async def pick(self, name: str) -> None:
            sheet = self.sheet()
            current = self.st(sheet.selected_name) if sheet.selected_name else None
            if current is not None and current.focus:
                await self.press("escape")
            elif getattr(self.focused, "id", None) == "patch_sheet_input":
                await self.press("escape")
            if getattr(self.focused, "id", None) != "patch_sheet_body":
                sheet.query_one(BODY).focus()
                await asyncio.sleep(0.05)
            names = self.names()
            if name not in names:
                raise AssertionError(f"{name!r} not on page")
            for _ in range(len(names) + 3):
                if sheet.selected_name == name:
                    return
                await self.press("down" if names.index(name) > names.index(sheet.selected_name) else "up")
            raise AssertionError(f"could not select {name!r}")

        async def open_bench(self, name: str, timeout: float = 150.0) -> None:
            await self.pick(name)
            if not await self._wait(lambda: self.st(name) is not None, 10):
                raise AssertionError("no bench state")
            if not self.st(name).focus:
                await self.press("enter")
            if not self.st(name).focus:
                raise AssertionError("Enter did not focus the bench")
            if not await self._wait(lambda: self.has_values(name), timeout):
                raise AssertionError(f"values of {name} never arrived")

        async def apply(self, key: str, operand: str, wait_preview: bool = True) -> None:
            name = self.sheet().selected_name
            await self.press(key, "enter")
            if getattr(self.focused, "id", None) != "patch_sheet_input":
                raise AssertionError("Enter did not reach the op input")
            self.sheet().query_one(INPUT, Input).value = operand
            keys_log.append(f"<set operand {operand!r}>")
            await self.press("enter")
            if wait_preview and not await self._wait(lambda: self.previewed(name), 60):
                raise AssertionError("preview did not finish")
            await self.press("escape")

        def snapshot(self) -> dict:
            win = self.query_one(WIN)
            row = painted_rows(self, win)[0]
            corner_style = painted_style(self, win.region.x, win.region.y)
            corner = getattr(getattr(corner_style, "color", None), "triplet", None)
            corner_hex = None if corner is None else corner.hex
            pill_at = row.find("BUSY")
            pill_style = painted_style(self, win.region.x + pill_at, win.region.y) if pill_at >= 0 else None
            fg = getattr(getattr(pill_style, "color", None), "triplet", None)
            bg = getattr(getattr(pill_style, "bgcolor", None), "triplet", None)
            match = PILL.search(row)
            title = win.border_title
            title_plain = title.plain if hasattr(title, "plain") else str(title)
            selected = self.sheet().selected_name
            state = self.st(selected) if selected else None
            job_name = match.group(3) if match else selected
            marked_row = next((row for row in self.sheet().rows if row.name == job_name), None)
            body = self.query_one(BODY)
            grid = self.query_one("#patch_sheet_grid")
            screen = tuple("".join(segment.text for segment in strip).rstrip() for strip in self.screen._compositor.render_strips())
            return {
                "time": time.monotonic(), "row": row, "corner": corner_hex, "title": title_plain,
                "pill_bold": getattr(pill_style, "bold", None), "pill_fg": getattr(fg, "hex", None),
                "pill_bg": getattr(bg, "hex", None), "match": match, "selected": selected,
                "state": state, "marked": getattr(marked_row, "is_staged", None),
                "app_size": f"{self.size.width}x{self.size.height}",
                "win_region": f"{win.region.x},{win.region.y},{win.region.width}x{win.region.height}",
                "win_size": f"{win.size.width}x{win.size.height}", "room_b": win.size.width - 4,
                "body": f"{body.size.width}x{body.size.height};content={body.content_size.width}x{body.content_size.height}",
                "grid": f"scroll_x={grid.scroll_x};size={grid.size.width}x{grid.size.height};virtual={grid.virtual_size.width}x{grid.virtual_size.height}",
                "sheet_top": self.sheet().top, "screen": screen,
            }

        async def visible_snapshot(self) -> dict:
            if args.size.startswith("80x"):
                self.query_one(WIN).scroll_visible(animate=False, top=True)
                await asyncio.sleep(0.05)
            return self.snapshot()

        async def wait_snapshot(self, predicate, timeout=30.0) -> dict:
            end = time.monotonic() + timeout
            last = None
            while time.monotonic() < end:
                last = await self.visible_snapshot()
                if predicate(last):
                    return last
                if args.release.exists():
                    raise TimeoutError("final close requested while waiting for painted state")
                await asyncio.sleep(0.02)
            match = last["match"] if last else None
            raise AssertionError(
                f"painted-state condition did not arrive; corner={last['corner'] if last else None}; "
                f"groups={match.groups() if match else None}; row={last['row'] if last else None!r}"
            )

        def sidecar(self, snap: dict, phase: str, png_name: str, pair=None) -> str:
            match = snap["match"]
            state = snap["state"]
            sheet = self.sheet()
            lines = [
                f"scene={scen}", f"capture_seq={self.capture_seq}", f"phase={phase}", f"png_name={png_name}",
                f"commit={args.commit}", f"fixture={self.fixture}",
                f"capture_timestamp={datetime.now(timezone.utc).isoformat()}", f"monotonic={snap['time']:.6f}",
                f"requested_size={args.size}", f"app_size={snap['app_size']}",
                f"patch_sheet_win_region={snap['win_region']}", f"patch_sheet_win_size={snap['win_size']}",
                f"title_room_B={snap['room_b']}", f"body={snap['body']}", f"grid={snap['grid']}",
                f"sheet_top={snap['sheet_top']}", f"focused={getattr(self.focused, 'id', None)}",
                f"selected={snap['selected']}", "page_rows=" + ", ".join(self.names()),
                f"sheet_subtitle={getattr(sheet, 'border_subtitle', None)!r}",
                f"painted_sheet_top_row={snap['row']}", f"painted_top_left_border_color={snap['corner']}",
                f"border_title_plain={snap['title']}", f"pill_bold={snap['pill_bold']}",
                f"pill_foreground={snap['pill_fg']}", f"pill_background={snap['pill_bg']}",
                f"spinner_glyph={match.group(1) if match else ''}", f"job_word={match.group(2) if match else ''}",
                f"busy_name={match.group(3) if match else ''}", f"pending_seconds={match.group(4) if match else ''}",
                f"different_from_f1={pair['different'] if pair else 'not-applicable'}",
                f"same_job_name={pair['same_job_name'] if pair else 'not-applicable'}",
                f"elapsed_nondecreasing={pair['nondecreasing'] if pair else 'not-applicable'}",
                f"frame_pair_valid={pair['valid'] if pair else 'not-applicable'}",
                f"frame_delta_s={pair['delta'] if pair else 'not-applicable'}",
                f"idle_title={snap['title'] == 'STAGING SHEET'}", f"busy_absent={'BUSY' not in snap['row']}",
                f"idle_border_not_busy={snap['corner'] != '#f5c26b'}",
                f"active_job={sheet._active_job[:2] if sheet._active_job else None}",
                f"record_hold={sheet._held}", f"record_stage_name={sheet._stage_name}",
            ]
            if state is not None:
                lines.append(
                    f"bench_state=cursor:{state.cursor};anchor:{state.anchor};tool:{state.tool};focus:{state.focus};"
                    f"edit:{dict(state.edit)};undo:{len(state.undo)};job:{state.job}"
                )
                lines.append(f"values_present={state.values is not None}")
                lines.append(f"preview_result_kind={type(state.preview).__name__ if state.preview is not None else None}")
            else:
                lines.extend(["values_present=False", "preview_result_kind=None"])
            entries = self.entries()
            lines.extend([
                f"document_entry_count_before={stage_counts['before']}", f"document_entry_count={len(entries)}",
                "document_entries=" + ",".join(f"0x{entry.address:X}:{len(entry.encoded_bytes)}" for entry in entries),
                f"ledger_row_count={self.query_one('#patch_doc_entries_table', DataTable).row_count}",
                f"staged_mark={snap['marked']}", f"write_landed_before_busy={scen == 'stage-refresh' and len(entries) > 0}",
                f"held_refresh_callbacks={refresh_state['held']}", f"held_refresh_callback_invocations={refresh_state['invoked']}",
                f"capture_frame_hold={snap['capture_frame_hold']}", f"presentation_settle_s={snap['presentation_settle_s']}",
                "frame_hold_painted_stable=True",
                f"decode_gate_target={sorted(holds['decode'])}", f"encode_gate_target={sorted(holds['encode'])}",
                f"decode_gate_entered={sorted(gate_entered['decode'])}", f"encode_gate_entered={sorted(gate_entered['encode'])}",
                f"decode_gate_released={gate_release['decode'].is_set()}", f"encode_gate_released={gate_release['encode'].is_set()}",
                "capture_interposition=" + ("held second refresh timer; callback resumed once after f2 ACK" if scen == "stage-refresh"
                    else "I-2 result-preserving gate; released after f2 ACK" if holds["decode"] or holds["encode"] else "none"),
                "keys_sent=" + " | ".join(keys_log), f"stub_os_writes={len(writes)}", f"app_is_running={self.is_running}",
            ])
            for widget_id in ("patch_sheet", "patch_inspector", "patch_editor_panel"):
                widget = self.query_one("#" + widget_id)
                lines.append(f"widget_#{widget_id}=size:{widget.size.width}x{widget.size.height};classes:{sorted(widget.classes)};subtitle:{getattr(widget, 'border_subtitle', None)!r}")
            for status in statuses[-8:]:
                lines.append(f"status={status}")
            lines.append("screen_text_begin")
            lines.extend(snap["screen"])
            lines.extend(["screen_text_end", "surface=ready"])
            return scrub("\n".join(lines) + "\n")

        async def report_and_ack(self, snap: dict, phase: str, png: Path, pair=None) -> None:
            frame_held = phase.startswith("busy")
            if frame_held:
                self.sheet()._busy_timer.pause()
            await asyncio.sleep(0.20)
            stable = await self.visible_snapshot()
            if stable["row"] != snap["row"]:
                if frame_held:
                    self.sheet()._busy_timer.resume()
                raise AssertionError("painted row changed before the capture report")
            stable["capture_frame_hold"] = frame_held
            stable["presentation_settle_s"] = 0.20
            self.capture_seq += 1
            report = self.sidecar(stable, phase, png.name, pair)
            temporary = args.report.with_name(args.report.name + f".{self.capture_seq}.tmp")
            temporary.write_text(report, encoding="utf-8", newline="\n")
            os.replace(temporary, args.report)
            ack_path = Path(f"{args.ack}.{self.capture_seq}")
            if not await self._wait(
                lambda: ack_path.exists() and ack_path.read_text(encoding="ascii").strip() == str(self.capture_seq), 30
            ):
                raise TimeoutError(f"capture ACK {self.capture_seq} did not arrive")
            if frame_held:
                self.sheet()._busy_timer.resume()

        def busy_match(self, snap: dict, word: str, name: str):
            match = snap["match"]
            if match is None or match.group(2) != word or snap["corner"] != "#f5c26b":
                return False
            if scen in NAME_SCENES:
                return True
            return match.group(3) == name

        async def busy_pair(self, word: str, name: str, ready=None) -> None:
            ready = ready or (lambda: True)
            first = await self.wait_snapshot(lambda snap: ready() and self.busy_match(snap, word, name), 90)
            self.first_busy = first
            await self.report_and_ack(first, "busy-f1", self.png_f1)

            def next_frame(snap):
                if not ready() or not self.busy_match(snap, word, name):
                    return False
                before, after = self.first_busy["match"], snap["match"]
                return (
                    snap["row"] != self.first_busy["row"]
                    and FRAMES[(FRAMES.index(before.group(1)) + 1) % 4] == after.group(1)
                    and after.group(2) == before.group(2) and after.group(3) == before.group(3)
                    and float(after.group(4)) >= float(before.group(4))
                )

            second = await self.wait_snapshot(next_frame, 10)
            before, after = self.first_busy["match"], second["match"]
            pair = {
                "different": True, "same_job_name": True, "nondecreasing": True,
                "valid": True, "delta": f"{second['time'] - self.first_busy['time']:.6f}",
            }
            await self.report_and_ack(second, "busy-f2", self.png_f2, pair)

        async def idle_capture(self, complete=None) -> None:
            complete = complete or (lambda: True)
            idle = await self.wait_snapshot(
                lambda snap: complete() and snap["title"] == "STAGING SHEET" and "BUSY" not in snap["row"]
                and snap["corner"] != "#f5c26b", 90,
            )
            await self.report_and_ack(idle, "idle", self.png_idle)

        async def settle_name_start(self, name: str) -> None:
            if not await self._wait(lambda: self.has_values(name), 90):
                raise AssertionError("startup decode did not finish")
            if not await self._wait(lambda: not self.sheet()._active_job and not self.sheet()._slot and not self.sheet()._page, 90):
                raise AssertionError("startup queue did not settle")

        async def quiesce_before_close(self) -> None:
            end = time.monotonic() + 180
            while time.monotonic() < end:
                sheet = self.sheet()
                if not sheet._active_job and not sheet._slot and not sheet._page and not sheet._records and not sheet._held:
                    return
                await asyncio.sleep(0.05)
            raise TimeoutError("bench queue did not quiesce before final close")

        async def scene_decode(self) -> None:
            await self.pick(SMALL)
            if not await self._wait(lambda: self.has_values(SMALL), 90):
                raise AssertionError("SMALL_BLK did not decode")
            holds["decode"].add(LARGE)
            await self.press("up", pause=0)
            await self.busy_pair("decode", LARGE)
            gate_release["decode"].set()
            await self.idle_capture(lambda: self.has_values(LARGE))

        async def scene_preview(self) -> None:
            await self.open_bench(VB)
            holds["encode"].add(VB)
            await self.apply("d", "5", wait_preview=False)
            await self.busy_pair("preview", VB)
            gate_release["encode"].set()
            await self.idle_capture(lambda: self.previewed(VB))

        async def scene_stage_encode(self) -> None:
            await self.open_bench(VB)
            await self.apply("s", "10")
            stage_counts["before"] = len(self.entries())
            holds["encode"].add(VB)
            await self.press("alt+s", pause=0)
            await self.busy_pair("stage", VB)
            gate_release["encode"].set()
            await self.idle_capture(lambda: len(self.entries()) == 1 and not self.sheet()._held)

        async def scene_stage_refused(self) -> None:
            await self.open_bench(VB)
            await self.apply("s", "60")
            stage_counts["before"] = len(self.entries())
            holds["encode"].add(VB)
            await self.press("alt+s", pause=0)
            await self.busy_pair("stage", VB)
            gate_release["encode"].set()
            refused = lambda: any("outside the limits -50..50" in status for status in statuses)
            await self.idle_capture(lambda: refused() and not self.entries() and not self.sheet()._held)
            await asyncio.sleep(0.3)
            if "BUSY" in self.snapshot()["row"]:
                raise AssertionError("busy cue returned after refusal")

        async def scene_stage_refresh(self) -> None:
            await self.open_bench(LARGE)
            await self.press(*(["shift+right"] * 15 + ["shift+down"] * 255), pause=0)
            await self.apply("s", "7")
            stage_counts["before"] = len(self.entries())
            callbacks = []
            real_set_timer = self.set_timer

            def hold_second_refresh(delay, callback):
                if len(self.entries()) > stage_counts["before"] and abs(delay - 0.1) < 0.0001:
                    callbacks.append(callback)
                    refresh_state["held"] = len(callbacks)
                    return None
                return real_set_timer(delay, callback)

            self.set_timer = hold_second_refresh
            await self.press("alt+s", pause=0)
            try:
                await self.busy_pair("stage", LARGE, lambda: len(callbacks) == 1 and len(self.entries()) == 1)
                del self.set_timer
                refresh_state["invoked"] += 1
                callbacks.pop(0)()
                await self.idle_capture(lambda: len(self.entries()) == 1 and not self.sheet()._held)
            finally:
                if "set_timer" in self.__dict__:
                    del self.set_timer

        async def scene_name(self) -> None:
            name = NAME_SCENES[scen]
            await self.settle_name_start(name)
            await self.pick("OTHER")
            await self.settle_name_start("OTHER")
            holds["decode"].add(name)
            await self.pick(name)
            await self.busy_pair("decode", name)
            gate_release["decode"].set()
            await self.wait_snapshot(
                lambda snap: snap["title"] == "STAGING SHEET" and "BUSY" not in snap["row"], 30
            )

        async def _drive(self) -> None:
            try:
                if scen in NAME_SCENES:
                    self.fixture = scen
                elif scen in ("decode", "stage-refresh"):
                    self.fixture = "large"
                else:
                    self.fixture = "defc"
                if self.fixture == "defc":
                    a2l_path, image_path = fx / "defc/definitions.a2l", fx / "defc/definitions.s19"
                else:
                    a2l_path, image_path = fx / f"{self.fixture}.a2l", fx / f"{self.fixture}.s19"
                self.load_a2l_from_path(a2l_path)
                if not await self._wait(lambda: bool(self._compute_a2l_enriched_tags()), 90):
                    raise TimeoutError("A2L load")
                if not await self._wait(lambda: self._running_session_action() is None, 90):
                    raise TimeoutError("A2L session action still running")
                self.load_from_path(image_path)
                if not await self._wait(lambda: self.current_file is not None, 60):
                    raise TimeoutError("image load")
                self.action_show_screen("patch")
                await asyncio.sleep(0.5)
                present = VB if self.fixture == "defc" else (LARGE if self.fixture == "large" else NAME_SCENES[scen])
                await self.open_sheet("_0001" if self.fixture == "defc" else "", present)
                if args.size != f"{self.size.width}x{self.size.height}":
                    raise AssertionError(f"requested {args.size}, actual {self.size.width}x{self.size.height}")
                self.png_f1 = args.png_f1
                base_name = str(args.png_f1)
                if not base_name.endswith(".f1.png"):
                    raise ValueError("--png-f1 must end in .f1.png")
                self.png_f2 = Path(base_name[:-7] + ".f2.png")
                self.png_idle = Path(base_name[:-7] + ".idle.png")
                if scen == "decode":
                    await self.scene_decode()
                elif scen == "preview":
                    await self.scene_preview()
                elif scen == "stage-encode":
                    await self.scene_stage_encode()
                elif scen == "stage-refused":
                    await self.scene_stage_refused()
                elif scen == "stage-refresh":
                    await self.scene_stage_refresh()
                else:
                    await self.scene_name()
                await self.quiesce_before_close()
            except BaseException as exc:
                self.capture_error = exc
                import traceback
                try:
                    snap = await self.visible_snapshot()
                except Exception:
                    snap = {"row": "", "screen": (), "time": time.monotonic()}
                self.capture_seq += 1
                text = scrub(
                    f"scene={scen}\ncapture_seq={self.capture_seq}\nphase=error\ncommit={args.commit}\n"
                    f"requested_size={args.size}\nkeys_sent={' | '.join(keys_log)}\n"
                    f"painted_sheet_top_row={snap.get('row', '')}\n"
                    f"surface=error {type(exc).__name__}: {exc}\n" + "\n".join(traceback.format_exc().splitlines()[-12:]) + "\n"
                )
                temporary = args.report.with_name(args.report.name + ".error.tmp")
                temporary.write_text(text, encoding="utf-8", newline="\n")
                os.replace(temporary, args.report)
            finally:
                for event in gate_release.values():
                    event.set()
                if not await self._wait(lambda: args.release.exists(), 180):
                    self.capture_error = self.capture_error or TimeoutError("final close release")
                self.exit(1 if self.capture_error else 0)

    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
