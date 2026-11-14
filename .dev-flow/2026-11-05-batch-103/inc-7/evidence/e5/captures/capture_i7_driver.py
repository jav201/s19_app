"""Inc 7 E5 capture driver (batch-103, HT-10 / X7): the REAL app, isolated state, real keys.

Run by capture_i7.ps1 under ``python -I -B`` in a fresh Windows Terminal window (adapted from
inc-8's CAP8 capture_i8_driver.py). It drives the A2L Explorer to the state one capture verdict
(CV-1 ... CV-11 of ``inc-7/E1-rulings.md`` section 5) asks for, through the app's own key handling
(``App._press_keys``, the call Textual's pilot uses) and, for a pasted list, a terminal paste event
(``events.Paste`` posted to the focused box, the route a bracketed paste takes), then writes a sidecar
of the state it actually reached (painted texts, widget regions, a hit test) and reports
``surface=ready``.

Fixture data only: case 08 written by the shipped ``tools/synth/make_release_case.py`` (seed 20260001,
1.0 MB, 462 tags) into the scratch folder; the hostile scenes rename two of its tags in a scratch copy
of the A2L. Pasted lists are invented names. The OS clipboard is never touched:
``write_os_clipboard``, ``read_os_clipboard`` and ``App.copy_to_clipboard`` are stubbed.

The same driver runs against the base tree (``63791549``) for the ``f2-typed`` scene only; it never
imports the Inc 7 module there.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
from pathlib import Path

SEED = 20260001
G2L_TEXT = (
    "VALUE_0002\nCURVE_0001, MAP_0003\nMEASUREMENT_0005\nVALUE_0042, CURVE_0017\nMAP_0024\n"
    "MAP_0001\nMEASUREMENT_0012, VALUE_0002\nCURVE_0071\nVALUE_0118\n"
)
HOSTILE = "H[red]\x1bQ\u202eZ\u200b_0003"  # replaces VALUE_0003 in the scratch A2L (no U+0085: a pasted list splits there)
LONG_NAME = "LONG_" + "X" * 1019  # 1,024 characters, replaces VALUE_0004 in the scratch A2L
MISSING_300 = "M" * 300

SCEN = (
    "layout", "scrolled", "text", "field-all", "drop-cuvre", "drop-0017", "drop-zzzz", "mode-invalid",
    "card-missing", "card-dup", "window", "window-big", "similar-11", "missing-25", "add-drop",
    "add-enter", "hostile", "hostile-drop", "long-drop", "unit300", "f2-typed",
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
    sys.path.insert(0, str(root / "tools" / "synth"))

    from textual import events
    from textual.app import App
    from textual.widgets import DataTable, Input

    import make_release_case as gen
    import s19_app.tui.os_clipboard_input as oci
    from s19_app.tui.app import S19TuiApp

    writes: list[int] = []

    def fake_write(text: str) -> bool:
        writes.append(len(text))
        return True

    def mirror_only(self, text: str) -> None:
        self._clipboard = text

    oci.write_os_clipboard = fake_write
    oci.read_os_clipboard = lambda *a, **k: None
    App.copy_to_clipboard = mirror_only

    base = args.base.resolve()
    case = base / "case08"
    case.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    scen = args.scenario
    gen.generate(case, SEED, 1.0)
    a2l_path, s19_path = case / "firmware.a2l", case / "firmware.s19"
    fixture = "case 08 (tools/synth/make_release_case.py generate, seed 20260001, 1.0 MB)"
    if scen in ("hostile", "hostile-drop", "long-drop"):
        text = a2l_path.read_text(encoding="utf-8")
        for old, new in (("VALUE_0003", HOSTILE), ("VALUE_0004", LONG_NAME)):
            text, n = re.subn(r"\b%s\b" % old, lambda _m, new=new: new, text)
            fixture += f"; scratch A2L copy: {old} renamed ({n} occurrences)"
        a2l_path = base / "hostile.a2l"
        a2l_path.write_text(text, encoding="utf-8", newline="\n")

    lines = [
        f"scenario={scen}",
        f"fixture={fixture}",
        "os_clipboard=stubbed (never touched)",
        "osc52=stubbed",
    ]

    class CaptureApp(S19TuiApp):
        CSS_PATH = str(root / "s19_app" / "tui" / "styles.tcss")

        def __init__(self) -> None:
            super().__init__(base_dir=base)

        def on_mount(self) -> None:
            super().on_mount()
            self._task = asyncio.create_task(self._drive())

        # ---- helpers -------------------------------------------------- #

        async def _wait(self, pred, timeout=30.0) -> bool:
            end = time.perf_counter() + timeout
            while time.perf_counter() < end:
                try:
                    if pred():
                        return True
                except Exception:  # noqa: BLE001
                    pass
                await asyncio.sleep(0.05)
            return False

        async def press(self, *keys: str, pause: float = 0.2) -> None:
            await self._press_keys(keys)
            await asyncio.sleep(pause)

        def q(self, sel: str):
            for screen in (self.screen, self.screen_stack[0]):
                found = list(screen.query(sel))
                if found:
                    return found[0]
            return None

        async def type_text(self, text: str) -> None:
            for ch in text:
                await self.press(ch, pause=0.04)
            await asyncio.sleep(0.6)

        async def focus(self, sel: str) -> None:
            self.q(sel).focus()
            await asyncio.sleep(0.3)

        async def paste(self, sel: str, text: str) -> None:
            widget = self.q(sel)
            widget.focus()
            await asyncio.sleep(0.2)
            # Posted to the app, as a terminal paste arrives: the app hands it to the
            # focused box once (posted to the widget, it bubbled and a TextArea took it twice).
            self.post_message(events.Paste(text))
            await asyncio.sleep(1.2)

        async def table_down(self, n: int) -> None:
            await self.focus("#a2l_tags_list")
            for _ in range(n):
                await self.press("down", pause=0.12)
            await asyncio.sleep(0.8)

        async def paste_g2(self) -> None:
            await self.paste("#a2l_tags_filter_input", G2L_TEXT)

        async def open_window(self) -> None:
            await self.focus("#a2l_tags_list")
            await self.press("alt+p", pause=0.6)
            if not await self._wait(lambda: type(self.screen).__name__ == "LabelListPasteModal", 10.0):
                raise AssertionError("alt+p did not open the paste window")
            await asyncio.sleep(1.5)

        def plain(self, widget) -> str:
            if widget is None:
                return "<absent>"
            rendered = widget.render()
            return getattr(rendered, "plain", None) or str(rendered)

        def facts(self) -> None:
            from textual.errors import NoWidget

            lines.append(f"top_screen={type(self.screen).__name__}")
            lines.append(f"focused={getattr(self.focused, 'id', None) or type(self.focused).__name__}")
            panes = self.q("#a2l_panes")
            if panes is not None:
                lines.append(f"body={panes.size.width}x{panes.size.height} classes={sorted(panes.classes)}")
            for sel in ("#a2l_tags_pane", "#a2l_hex_pane", "#a2l_detail_card", "#a2l_tags_filters",
                        "#a2l_tags_filter_input", "#a2l_tag_find_input", "#a2l_paste_list_button",
                        "#a2l_filter_suggest", "#a2l_list_chips", "#a2l_list_missing", "#a2l_tags_list",
                        "#alt_hex_scroll", "#a2l_list_add_suggest", "#a2l_list_add"):
                widget = self.q(sel)
                if widget is None:
                    continue
                try:
                    seen = widget.screen.find_widget(widget).visible_region
                except NoWidget:
                    seen = None
                hit = None
                if seen is not None and seen.area:
                    try:
                        hit = widget.screen.get_widget_at(*seen.center)[0]
                    except NoWidget:
                        hit = None
                extra = ""
                if isinstance(widget, Input):
                    extra = f" content_width={widget.content_region.width} value_len={len(widget.value)}"
                if isinstance(widget, DataTable):
                    extra = f" rows={widget.row_count} body_rows={max(0, widget.size.height - 1)}"
                lines.append(
                    f"region {sel}: {widget.region} visible={seen} display={widget.display}"
                    f" hit_at_centre={getattr(hit, 'id', None) or type(hit).__name__}{extra}"
                )
            for sel in ("#a2l_filter_mode_tag", "#a2l_list_chips", "#a2l_list_missing",
                        "#a2l_tags_summary", "#a2l_filter_suggest", "#a2l_list_counts",
                        "#a2l_list_ribbon", "#a2l_list_more", "#a2l_list_missing",
                        "#a2l_list_similar", "#a2l_list_add_suggest"):
                widget = self.q(sel)
                if widget is not None and widget.display:
                    for i, ln in enumerate(self.plain(widget).splitlines()):
                        lines.append(f"text {sel}[{i}]: {ln[:300]!r}")
            card = self.q("#a2l_detail_card")
            if card is not None:
                for i, strip in enumerate(getattr(card, "lines", [])[:20]):
                    lines.append(f"text #a2l_detail_card[{i}]: {strip.text.rstrip()[:300]!r}")
            hexv = self.q("#alt_hex_view")
            if hexv is not None:
                hex_lines = self.plain(hexv).splitlines()
                scroll = self.q("#alt_hex_scroll")
                width = scroll.scrollable_content_region.width if scroll is not None else -1
                longest = max((len(x) for x in hex_lines), default=0)
                lines.append(f"hex_rows={len(hex_lines)} longest_row={longest} hex_scroll_width={width}")
            table = self.q("#a2l_tags_list")
            if table is not None and table.row_count:
                labels = [c.label.plain for c in table.ordered_columns]
                lines.append(f"table_columns={labels}")
                lines.append(f"table_cursor_row={table.cursor_row} scroll_x={table.scroll_x}")
                for i in range(min(table.row_count, 14)):
                    cells = [getattr(c, "plain", str(c)) for c in table.get_row_at(i)]
                    lines.append(f"table_row[{i}]: {[c[:40] for c in cells[:6]]!r}")
            area = self.q("#a2l_list_text")
            if area is not None:
                lines.append(f"text_area_lines={area.document.line_count} first={area.document.get_line(0)[:80]!r}")
            strips = self.screen._compositor.render_strips()
            lines.append("screen_begin")
            for strip in strips:
                lines.append("| " + strip.text.rstrip())
            lines.append("screen_end")

        # ---- the drive ------------------------------------------------ #

        async def _drive(self) -> None:
            try:
                await asyncio.sleep(0.5)
                self.load_selected_file(s19_path)
                if not await self._wait(lambda: self.current_file is not None, 60.0):
                    raise TimeoutError("image load")
                self.load_a2l_from_path(a2l_path)
                if not await self._wait(lambda: bool(self._a2l_enriched_tags), 90.0):
                    raise TimeoutError("a2l load")
                if a2l_path.name == "hostile.a2l" and not await self._wait(
                    lambda: any(t.get("name") == HOSTILE for t in self._a2l_enriched_tags), 90.0
                ):
                    lines.append("hostile tag: NOT among the loaded tags (the parser dropped or changed it)")
                await asyncio.sleep(0.8)
                self.action_show_screen("a2l")
                await asyncio.sleep(1.5)
                lines.append(f"app_size={self.size.width}x{self.size.height}")
                lines.append(f"a2l_tags={len(self._a2l_enriched_tags)}")
                await getattr(self, "sc_" + scen.replace("-", "_"))()
                await asyncio.sleep(0.8)
                self.facts()
                lines.append(f"stub_os_writes={len(writes)}")
                lines.append("surface=ready")
            except BaseException as exc:  # noqa: BLE001
                import traceback
                lines.append(f"surface=error {type(exc).__name__}: {exc}")
                lines.extend("  " + ln for ln in traceback.format_exc().splitlines()[-10:])
            finally:
                if args.report is not None:
                    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
                if args.release is not None:
                    await self._wait(lambda: args.release.exists(), 180.0)
                self.exit(0)

        # ---- scenarios (CV ids of inc-7/E1-rulings.md section 5) ------ #

        async def sc_layout(self):  # CV-1, CV-3, F-I7-1, BL-I7-6: G2 list pasted, row 2 (found), enter -> hex jump
            await self.paste_g2()
            await self.table_down(1)
            await self.press("enter", pause=1.0)

        async def sc_scrolled(self):  # CV-3: the list table scrolled right (fixed # and Tag)
            await self.paste_g2()
            await self.table_down(1)
            await self.press("enter", pause=1.0)
            await self.focus("#a2l_tags_list")
            for _ in range(8):
                await self.press("right", pause=0.12)
            await asyncio.sleep(0.6)

        async def sc_text(self):  # CV-5 text mode, D-4 text-mode columns: `VALUE` typed
            await self.focus("#a2l_tags_filter_input")
            await self.type_text("VALUE")
            await self.table_down(1)

        async def sc_field_all(self):  # CV-2: field all, `synthetic demo` typed -> list of 2 missing
            self._set_a2l_filter_field("all")
            await asyncio.sleep(0.4)
            await self.focus("#a2l_tags_filter_input")
            await self.type_text("synthetic demo")

        async def _drop(self, query: str):  # CV-4, P-087 a: the filter box's dropdown
            await self.focus("#a2l_tags_filter_input")
            await self.type_text(query)
            if not await self._wait(lambda: self.q("#a2l_filter_suggest").is_open, 8.0):
                raise AssertionError(f"dropdown did not open for {query!r}")
            await asyncio.sleep(0.5)

        async def sc_drop_cuvre(self):
            await self._drop("cuvre_00")

        async def sc_drop_0017(self):
            await self._drop("0017")

        async def sc_drop_zzzz(self):
            await self._drop("zzzz")

        async def sc_mode_invalid(self):  # CV-5 mode line, CV-9 hidden card: G2 list, mode Invalid, row 1
            await self.paste_g2()
            self.q("#a2l_filter_invalid").press()
            await asyncio.sleep(1.0)
            await self.table_down(1)
            await self.press("up", pause=0.8)

        async def sc_card_missing(self):  # CV-9: row 7 MAP_0024 (missing) -> card with closest names
            await self.paste_g2()
            await self.table_down(6)
            await asyncio.sleep(1.0)

        async def sc_card_dup(self):  # CV-9: row 10 (duplicate of #1)
            await self.paste_g2()
            await self.table_down(9)

        async def sc_window(self):  # CV-6, CV-7, D-7: alt+p from list mode (prefilled), similar lines
            await self.paste_g2()
            await self.open_window()

        async def sc_window_big(self):  # CV-6 more line: 4,906 names pasted into the window
            await self.open_window()
            names = [t.get("name") for t in self._a2l_enriched_tags]
            big = "\n".join(names[i % len(names)] for i in range(4906))
            await self.paste("#a2l_list_text", big)
            await asyncio.sleep(2.0)

        async def sc_similar_11(self):  # CV-7: 11 missing names -> the first-10 cut line
            await self.open_window()
            text = "\n".join([f"MAP_9{i:03d}" for i in range(11)] + ["VALUE_0002", "MAP_0003"])
            await self.paste("#a2l_list_text", text)
            await asyncio.sleep(2.0)

        async def sc_missing_25(self):  # CV-8: 25 missing names in the viewer -> ` +5`
            text = "\n".join([f"MAP_9{i:03d}" for i in range(25)] + ["VALUE_0002", "MAP_0003"])
            await self.paste("#a2l_tags_filter_input", text)
            await self.table_down(1)

        async def sc_add_drop(self):  # CV-10: the add line's dropdown for `0042 val`
            await self.paste_g2()
            await self.open_window()
            await self.focus("#a2l_list_add")
            await self.type_text("0042 val")
            await self._wait(lambda: self.q("#a2l_list_add_suggest").is_open, 8.0)
            await asyncio.sleep(0.5)

        async def sc_add_enter(self):  # CV-10: enter appends the chosen name to the text area
            await self.sc_add_drop()
            await self.press("enter", pause=1.2)

        async def sc_hostile(self):  # CV-11: hostile tag name, a 300-character missing name, card of row 1
            box = self.q("#a2l_tags_filter_input")
            box.value = f"{HOSTILE}, {MISSING_300}, MAP_0003"
            lines.append("filter set: box.value (a hostile name holds controls a paste would strip)")
            await asyncio.sleep(1.2)
            await self.table_down(1)
            await self.press("up", pause=0.8)

        async def sc_hostile_drop(self):  # CV-11: the dropdown row of the hostile tag name
            await self._drop("z_0003")

        async def sc_long_drop(self):  # CV-11: a 1,024-character tag name in the dropdown
            await self._drop("LONG_")

        async def sc_unit300(self):  # CV-11: a 300-character text with NUL and TAB in field unit
            self._set_a2l_filter_field("unit")
            await asyncio.sleep(0.4)
            box = self.q("#a2l_tags_filter_input")
            box.value = "".join("\x00" if i == 10 else "\t" if i == 20 else "u" for i in range(300))
            lines.append("filter set: box.value (NUL cannot be typed)")
            await asyncio.sleep(1.2)

        async def sc_f2_typed(self):  # F-I7-2: typed text in the filter and the find box (base and tree)
            await self.focus("#a2l_tags_filter_input")
            await self.type_text("VALUE_0002")
            await self.focus("#a2l_tag_find_input")
            await self.type_text("MAP")

    CaptureApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
