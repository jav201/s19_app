#!/usr/bin/env python
"""THROWAWAY in-APP prototype — command-bar variants + A2B diff variants, mounted
INSIDE the real S19TuiApp (real chrome, rail, footer, styles.tcss, real renderers).

Pattern: crc_designer.b59.inapp_prototype.py (sub-shape A). Shipped widget ids are
reused so live handlers stay wired; hex windows render through the REAL
render_hex_view_text (incl. its highlight path). No writes anywhere.

Run live:   python prototypes/cmdbar_a2bdiff.tui_prototype.py cmdbar A|B|C
            python prototypes/cmdbar_a2bdiff.tui_prototype.py diff A|B|C
Screenshot: python prototypes/cmdbar_a2bdiff.tui_prototype.py shot
            -> prototypes/cmdbar_*.120w.svg + abdiff_*.120w.svg (textual==8.2.8)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from rich.text import Text
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, Label, ListItem, ListView, Select, Static

from s19_app.compare import diff_mem_maps
from s19_app.tui import app as app_mod
from s19_app.tui.command_bar import CommandBar
from s19_app.tui.hexview import HEX_WIDTH, render_hex_view_text
from s19_app.tui.models import LoadedFile
from s19_app.tui.os_clipboard_input import OsClipboardInput
from s19_app.tui.screens_directionb import AbDiffPanel

HERE = Path(__file__).resolve().parent

ACCENT = "#91abec"
DIM = "#6b7280"
FG = "#e9e9e9"
KIND = {"changed": "#d9a35b", "only_a": "#e06c75", "only_b": "#4ec9d4"}
KIND_LABEL = {"changed": "chg", "only_a": "onlyA", "only_b": "onlyB"}


# ==========================================================================
# Fixtures — a workspace image, and an A/B pair with all three run kinds.
# Runs come from the REAL diff engine (diff_mem_maps), never hand-typed.
# ==========================================================================

def _workspace_fixture() -> LoadedFile:
    mem = {}
    for i in range(0x140):                       # 0x0100-0x023F contiguous
        mem[0x100 + i] = (i * 7) & 0xFF
    for i, ch in enumerate(b"MOT_CAL_A\x00\x00\x00\x00\x00\x124Vx"):
        mem[0x1000 + i] = ch
    for i in range(0x40):
        mem[0x1010 + i] = (0x30 + i) & 0xFF
    bases = sorted({a - a % HEX_WIDTH for a in mem})
    return LoadedFile(
        path=Path("demo.s19"), file_type="s19", mem_map=mem, row_bases=bases,
        ranges=[(0x100, 0x240), (0x1000, 0x1050)], range_validity=[True, True],
        errors=[], a2l_path=None, a2l_data=None,
    )


def _diff_fixture():
    a, b = {}, {}

    def both(addr, data):
        for i, v in enumerate(data):
            a[addr + i] = v
            b[addr + i] = v

    both(0x100, [(i * 7) & 0xFF for i in range(0x40)])
    a[0x110], a[0x111] = 0xA2, 0x00              # run: changed, 2 B
    b[0x110], b[0x111] = 0xFF, 0x1C
    both(0x230, [0x00] * 0x30)
    for i, v in enumerate([0xDE, 0xAD, 0xBE, 0xEF]):
        a[0x240 + i] = v
    for i, v in enumerate([0xCA, 0xFE, 0xBA, 0xBE]):
        b[0x240 + i] = v
    both(0xFF0, [0x00] * 0x10)
    both(0x1000, list(b"MOT_CAL_"))              # identical 8-byte tag prefix
    for i in range(8, 0x40):                     # then every byte differs:
        a[0x1000 + i] = (0x50 + i) & 0xFF        # one clean 56-byte changed run
        b[0x1000 + i] = (0xA0 + i) & 0xFF
    both(0x1040, [0x00] * 0x10)
    for i in range(0x40):                        # only_b block
        b[0x2000 + i] = (0x11 + i) & 0xFF
    for i in range(0x10):                        # only_a block
        a[0x4000 + i] = (0xE0 + i) & 0xFF
    both(0x5540, [0x22] * 0x10)
    a[0x5550], a[0x5551] = 0x01, 0x02            # final changed pair
    b[0x5550], b[0x5551] = 0x03, 0x04

    runs, stats = diff_mem_maps(a, b)
    return a, b, [(r.start, r.end, r.kind) for r in runs], stats


# ==========================================================================
# Command-bar variants (patch app_mod.CommandBar)
# ==========================================================================

class CmdBarA(CommandBar):
    """Variant A — bar deleted; find/goto live on a transient summon line."""

    DEFAULT_CSS = "CmdBarA { height: 0; }"

    def compose(self):
        with Vertical(id="command_palette", classes="hidden"):
            yield OsClipboardInput(placeholder="Command palette  (Ctrl+K)", id="palette_input")
            yield ListView(id="palette_list")
        # keep the real input ids alive (hidden) so `/` and `g` handlers stay wired
        with Container(classes="hidden"):
            yield OsClipboardInput(id="find_input")
            yield OsClipboardInput(id="cmdbar_goto_input")


class SummonLine(Container):
    """Variant A's transient command line (appears on `/` or `g`, Esc closes)."""

    DEFAULT_CSS = """
    SummonLine { dock: bottom; height: 1; layout: horizontal; background: #1a2440; }
    SummonLine #proto_summon_key { width: 9; color: #91abec; text-style: bold; }
    SummonLine #proto_summon_input {
        width: 1fr; height: 1; border: none; padding: 0; background: #1a2440;
    }
    SummonLine #proto_summon_hint { width: 24; color: #6b7280; }
    """

    def compose(self):
        yield Label(" / find:", id="proto_summon_key", markup=False)
        yield OsClipboardInput(id="proto_summon_input")
        yield Label("Enter run · Esc close", id="proto_summon_hint", markup=False)


class CmdBarB(CommandBar):
    """Variant B — same widgets, one honest borderless row (ids preserved)."""

    DEFAULT_CSS = """
    CmdBarB #proto_bar_row { height: 1; width: 100%; background: #0f1525; }
    CmdBarB #proto_prompt { width: 2; color: #91abec; text-style: bold; }
    CmdBarB #proto_ctx { width: auto; color: #6b7280; padding: 0 1; }
    CmdBarB .proto-key { width: 4; color: #91abec; text-style: bold; padding: 0 1; }
    CmdBarB #find_input, CmdBarB #cmdbar_goto_input {
        width: 1fr; height: 1; border: none; padding: 0; background: #1a2440;
    }
    """

    def compose(self):
        with Horizontal(id="proto_bar_row"):
            yield Label("›", id="proto_prompt", markup=False)
            yield Label("proj S19_demo · a2l demo.a2l", id="proto_ctx", markup=False)
            yield Label("/", classes="proto-key", markup=False)
            yield OsClipboardInput(placeholder="find ASCII", id="find_input")
            yield Label("g", classes="proto-key", markup=False)
            yield OsClipboardInput(placeholder="goto 0xADDR", id="cmdbar_goto_input")
        with Vertical(id="command_palette", classes="hidden"):
            yield OsClipboardInput(placeholder="Command palette  (Ctrl+K)", id="palette_input")
            yield ListView(id="palette_list")


class CmdBarC(CommandBar):
    """Variant C — status strip only; `/`·`g` route into the palette prompt."""

    DEFAULT_CSS = """
    CmdBarC #proto_strip { height: 1; width: 100%; background: #0f1525; }
    CmdBarC #proto_prompt { width: 2; color: #91abec; text-style: bold; }
    CmdBarC #proto_ctx { width: 1fr; color: #e9e9e9; padding: 0 1; }
    CmdBarC #proto_hint { width: 28; color: #6b7280; }
    """

    def compose(self):
        with Horizontal(id="proto_strip"):
            yield Label("›", id="proto_prompt", markup=False)
            yield Label("S19_demo · demo.a2l", id="proto_ctx", markup=False)
            yield Label("/ find · g goto · ^K cmds", id="proto_hint", markup=False)
        with Vertical(id="command_palette", classes="hidden"):
            yield OsClipboardInput(placeholder="find:", id="palette_input")
            yield ListView(id="palette_list")
        with Container(classes="hidden"):
            yield OsClipboardInput(id="find_input")
            yield OsClipboardInput(id="cmdbar_goto_input")


# ==========================================================================
# A2B diff variants (patch app_mod.AbDiffPanel). Selection/action rows are
# kept verbatim (same ids -> Compare/Report handlers stay wired); only the
# RESULTS area changes shape. Windows render via the real render_hex_view_text.
# ==========================================================================

# Redesign includes compacting the shipped selection/action rows to one line
# each (Input/Button/Select default to 3 rows and starve the results area).
# Class-scoped so the subclass CSS outranks styles.tcss on the shared ids;
# the contested row containers additionally get inline styles (_apply_compact).
def _compact_css(cls: str) -> str:
    return f"""
{cls} #diff_select_row_a, {cls} #diff_select_row_b, {cls} #diff_action_row {{
    height: 1; margin-bottom: 0;
}}
{cls} #diff_select_row_a Select, {cls} #diff_select_row_b Select {{ display: none; }}
{cls} .diff-field-label {{ width: 3; height: 1; }}
{cls} #diff_path_a, {cls} #diff_path_b, {cls} #diff_report_dest {{
    height: 1; border: none; padding: 0 1; background: #1a2440; margin-left: 1;
}}
{cls} #diff_compare_button, {cls} #diff_report_button {{
    height: 1; border: none; min-width: 11; margin-right: 1;
}}
{cls} #diff_status {{ height: 1; margin-bottom: 1; }}
"""


def _apply_compact(panel) -> None:
    """Inline styles for the boxes styles.tcss also targets (inline wins)."""
    panel.styles.padding = (1, 1)
    for sel in ("#diff_select_row_a", "#diff_select_row_b", "#diff_action_row",
                "#diff_status"):
        w = panel.query_one(sel)
        w.styles.height = 1
        w.styles.margin = 0
    panel.query_one("#diff_status").styles.margin = (0, 0, 1, 0)


def _selection_rows():
    empty = [("(external path below)", AbDiffPanel._EXTERNAL_OPTION)]
    yield Horizontal(
        Label("A:", classes="diff-field-label"),
        Select(empty, id="diff_select_a", allow_blank=False),
        OsClipboardInput(placeholder="external path A", id="diff_path_a"),
        id="diff_select_row_a",
    )
    yield Horizontal(
        Label("B:", classes="diff-field-label"),
        Select(empty, id="diff_select_b", allow_blank=False),
        OsClipboardInput(placeholder="external path B", id="diff_path_b"),
        id="diff_select_row_b",
    )
    yield Horizontal(
        Button("Compare", id="diff_compare_button"),
        Button("Report", id="diff_report_button"),
        OsClipboardInput(
            placeholder="report destination dir (no-project only)",
            id="diff_report_dest",
        ),
        id="diff_action_row",
    )
    yield Static("Select two images and press Compare.", id="diff_status",
                 classes="sev-info", markup=False)


def _summary_text(runs, stats) -> Text:
    t = Text()
    t.append(f"{len(runs)} runs", style="bold " + FG)
    t.append("  ·  ", style=DIM)
    t.append(f"{stats.run_counts['changed']} changed", style=KIND["changed"])
    t.append("  ·  ", style=DIM)
    t.append(f"{stats.run_counts['only_a']} only-A", style=KIND["only_a"])
    t.append("  ·  ", style=DIM)
    t.append(f"{stats.run_counts['only_b']} only-B", style=KIND["only_b"])
    t.append("      n/p run · Enter jump · j/k select", style=DIM)
    return t


def _window_text(mem, start, end, context_bytes) -> Text:
    low = max(0, start - context_bytes)
    low -= low % HEX_WIDTH
    high = end + context_bytes
    rows = list(range(low, high, HEX_WIDTH))
    return render_hex_view_text(mem, None, rows, (start, end), max_rows=64)


class DiffVariantA(AbDiffPanel):
    """Variant A — master–detail: selectable run list + stacked full-width windows."""

    DEFAULT_CSS = _compact_css("DiffVariantA") + """
    DiffVariantA { padding: 1 1; }
    DiffVariantA #proto_summary { height: 1; margin-bottom: 1; }
    DiffVariantA #proto_a_cols { height: 1fr; }
    DiffVariantA #proto_run_list { width: 22; height: 100%; border: round #1b233a; }
    DiffVariantA #proto_run_list > ListItem { padding: 0 1; }
    DiffVariantA #proto_windows { width: 1fr; height: 100%; }
    DiffVariantA ScrollableContainer { scrollbar-size: 1 1; }
    DiffVariantA #proto_win_a, DiffVariantA #proto_win_b {
        height: 1fr; border: round #1b233a; padding: 0; overflow: auto;
    }
    """

    def compose(self):
        yield from _selection_rows()
        yield Static("", id="proto_summary", markup=False)
        yield Horizontal(
            ListView(id="proto_run_list"),
            Vertical(
                ScrollableContainer(Static("", id="proto_win_a", markup=False)),
                ScrollableContainer(Static("", id="proto_win_b", markup=False)),
                id="proto_windows",
            ),
            id="proto_a_cols",
        )

    def proto_render(self, runs, mem_a, mem_b, stats, selected: int = 2) -> None:
        _apply_compact(self)
        self._proto_runs, self._proto_a, self._proto_b = runs, mem_a, mem_b
        self.query_one("#diff_status", Static).update(
            f"Compared variant_base vs variant_new — {len(runs)} differing runs.")
        self.query_one("#proto_summary", Static).update(_summary_text(runs, stats))
        lv = self.query_one("#proto_run_list", ListView)
        lv.clear()
        for i, (start, end, kind) in enumerate(runs):
            row = Text()
            row.append(f"{i:>3} ", style=DIM)
            row.append(f"0x{start:08X} ", style=KIND[kind])
            row.append(f"+{end - start:<5}", style=KIND[kind])
            row.append(f" {KIND_LABEL[kind]}", style=KIND[kind])
            lv.append(ListItem(Label(row)))
        lv.index = selected
        lv.focus()
        self._proto_windows(selected)

    def _proto_windows(self, index: int) -> None:
        start, end, kind = self._proto_runs[index]
        header = f"Run #{index}  0x{start:08X}-0x{end:08X}  {KIND_LABEL[kind]}"
        # context grows to fill the pane: rows derived from the REAL container
        # height at render time, run anchored one context row from the top
        cont_h = self.query_one("#proto_windows").size.height or 20
        content_rows = max(4, cont_h // 2 - 3)
        first = max(0, (start - start % HEX_WIDTH) - HEX_WIDTH)
        rows = [first + i * HEX_WIDTH for i in range(content_rows)]
        for wid, mem, label in (("#proto_win_a", self._proto_a, "Image A"),
                                ("#proto_win_b", self._proto_b, "Image B")):
            body = Text()
            body.append(f"{label} — {header}\n", style="bold " + KIND[kind])
            body.append_text(render_hex_view_text(mem, None, rows, (start, end)))
            self.query_one(wid, Static).update(body)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if getattr(self, "_proto_runs", None) and event.list_view.index is not None:
            self._proto_windows(event.list_view.index)


class DiffVariantB(AbDiffPanel):
    """Variant B — unified interleaved stream, one full-width scroll pane."""

    DEFAULT_CSS = _compact_css("DiffVariantB") + """
    DiffVariantB #proto_summary { height: 1; margin-bottom: 1; }
    DiffVariantB #proto_stream_wrap { height: 1fr; border: round #1b233a; }
    DiffVariantB #proto_stream { padding: 0 1; }
    """

    def compose(self):
        yield from _selection_rows()
        yield Static("", id="proto_summary", markup=False)
        yield ScrollableContainer(
            Static("", id="proto_stream", markup=False), id="proto_stream_wrap")

    def proto_render(self, runs, mem_a, mem_b, stats, selected: int = 2) -> None:
        _apply_compact(self)
        self.query_one("#diff_status", Static).update(
            f"Compared variant_base vs variant_new — {len(runs)} differing runs.")
        self.query_one("#proto_summary", Static).update(_summary_text(runs, stats))
        out = Text()
        for i, (start, end, kind) in enumerate(runs):
            head = f"══ Run #{i}  0x{start:08X}-0x{end:08X}  {KIND_LABEL[kind]}"
            head += f"  ({end - start} bytes) "
            out.append(head.ljust(96, "═") + "\n", style=KIND[kind])
            low = max(0, start - HEX_WIDTH)
            low -= low % HEX_WIDTH
            for base in range(low, end + HEX_WIDTH, HEX_WIDTH):
                in_run = not (base + HEX_WIDTH <= start or base >= end)
                pairs = ((("A ", KIND["only_a"]), mem_a),
                         (("B ", KIND["only_b"]), mem_b)) if in_run else \
                        (((". ", DIM), mem_a),)
                for (gutter, gstyle), mem in pairs:
                    if not any(base + o in mem for o in range(HEX_WIDTH)):
                        continue
                    out.append(gutter, style="bold " + gstyle)
                    out.append_text(render_hex_view_text(
                        mem, None, [base], (start, end) if in_run else None))
                    if not str(out).endswith("\n"):
                        out.append("\n")
        self.query_one("#proto_stream", Static).update(out)


class DiffVariantC(AbDiffPanel):
    """Variant C — linked full-height panes + a change-map rail (memstrip idiom)."""

    DEFAULT_CSS = _compact_css("DiffVariantC") + """
    DiffVariantC #proto_summary { height: 1; margin-bottom: 1; }
    DiffVariantC #proto_c_cols { height: 1fr; }
    DiffVariantC #proto_pane_a, DiffVariantC #proto_pane_b {
        width: 1fr; height: 100%; border: round #1b233a; padding: 0 1; overflow: auto;
    }
    DiffVariantC #proto_rail { width: 3; height: 100%; padding: 0 1; }
    """

    def compose(self):
        yield from _selection_rows()
        yield Static("", id="proto_summary", markup=False)
        yield Horizontal(
            ScrollableContainer(Static("", id="proto_pane_a", markup=False)),
            ScrollableContainer(Static("", id="proto_pane_b", markup=False)),
            Static("", id="proto_rail", markup=False),
            id="proto_c_cols",
        )

    def proto_render(self, runs, mem_a, mem_b, stats, selected: int = 2) -> None:
        _apply_compact(self)
        self.query_one("#diff_status", Static).update(
            f"Compared variant_base vs variant_new — {len(runs)} differing runs.")
        self.query_one("#proto_summary", Static).update(_summary_text(runs, stats))
        sel_start, sel_end, _sel_kind = runs[selected]
        for wid, mem, label in (("#proto_pane_a", mem_a, "A  (viewport @ selected run"
                                 f" #{selected})"),
                                ("#proto_pane_b", mem_b, "B")):
            body = Text()
            body.append(label + "\n", style="bold " + ACCENT)
            body.append_text(_window_text(mem, sel_start, sel_end, 64))
            self.query_one(wid, Static).update(body)
        # rail: whole union span folded onto ~26 rows, one glyph per row
        lo = min(r[0] for r in runs)
        hi = max(r[1] for r in runs)
        rows = 26
        rail = Text()
        for row in range(rows):
            lo_r = lo + (hi - lo) * row // rows
            hi_r = lo + (hi - lo) * (row + 1) // rows
            hit = next((k for s, e, k in runs if s < hi_r and e > lo_r), None)
            marker = "◄" if (lo_r <= sel_start < hi_r) else ""
            rail.append("█" if hit else "│", style=KIND.get(hit, "#3a4152"))
            rail.append(marker + "\n", style="bold " + ACCENT)
        self.query_one("#proto_rail", Static).update(rail)


# ==========================================================================
# Drivers — live run + headless SVG captures (textual==8.2.8)
# ==========================================================================

CMDBAR = {"A": CmdBarA, "B": CmdBarB, "C": CmdBarC}
DIFF = {"A": DiffVariantA, "B": DiffVariantB, "C": DiffVariantC}


def _present_workspace(app) -> None:
    app.current_file = _workspace_fixture()
    for call in (app.update_hex_view, app.update_sections,
                 app.update_memory_strip, app._refresh_loaded_panel,
                 app._apply_empty_state):
        try:
            call()
        except Exception as exc:  # noqa: BLE001 — prototype: surface, keep going
            print(f"  [present] {call.__name__}: {type(exc).__name__}: {exc}")


async def _drive_cmdbar(pilot, app, variant: str) -> None:
    _present_workspace(app)
    await pilot.pause()
    if variant == "A":
        await app.mount(SummonLine())
        await pilot.pause()
        app.query_one("#proto_summon_input", OsClipboardInput).value = "MOT_CAL"
    elif variant == "B":
        app.query_one("#find_input", OsClipboardInput).value = "MOT_CAL"
        app.query_one("#find_input").focus()
    elif variant == "C":
        bar = app.query_one("#command_palette")
        bar.remove_class("hidden")
        app.query_one("#palette_input", OsClipboardInput).value = "find: MOT_CAL"
    await pilot.pause()


async def _drive_diff(pilot, app, variant: Optional[str]) -> None:
    app.current_file = _workspace_fixture()
    await pilot.press("7")
    await pilot.pause()
    await pilot.pause()
    mem_a, mem_b, runs, stats = _diff_fixture()
    panel = app.query_one("#ab_diff_panel")
    if variant is None:  # baseline — the shipped panel's real render path
        panel.render_comparison(runs, mem_a, mem_b, "both (2)", "both (2)")
        panel.set_status(
            f"Compared variant_base vs variant_new — {len(runs)} differing runs.",
            "sev-info")
    else:
        panel.query_one("#diff_path_a").value = "variant_base"
        panel.query_one("#diff_path_b").value = "variant_new"
        panel.proto_render(runs, mem_a, mem_b, stats)
    await pilot.pause()
    await pilot.pause()


def _shot() -> None:
    import asyncio

    async def snap(name, size, cmdbar_cls, diff_variant, drive):
        if cmdbar_cls is not None:
            app_mod.CommandBar = cmdbar_cls
        else:
            app_mod.CommandBar = CommandBar
        app_mod.AbDiffPanel = DIFF.get(diff_variant, AbDiffPanel) \
            if diff_variant else AbDiffPanel
        app = app_mod.S19TuiApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await drive(pilot, app)
            path = HERE / f"{name}.{size[0]}w.svg"
            app.save_screenshot(str(path))
            print(f"wrote {path.name}")

    async def main():
        # command bar: baseline + A/B/C on the populated workspace
        await snap("cmdbar_baseline", (120, 34), None, None,
                   lambda p, a: _drive_cmdbar(p, a, "baseline"))
        for v in "ABC":
            await snap(f"cmdbar_variant_{v}", (120, 34), CMDBAR[v], None,
                       lambda p, a, v=v: _drive_cmdbar(p, a, v))
        # diff: baseline + A/B/C
        await snap("abdiff_baseline", (132, 44), None, None,
                   lambda p, a: _drive_diff(p, a, None))
        for v in "ABC":
            await snap(f"abdiff_variant_{v}", (132, 44), None, v,
                       lambda p, a, v=v: _drive_diff(p, a, v))

    asyncio.run(main())


def _live(kind: str, variant: str) -> None:
    if kind == "cmdbar":
        app_mod.CommandBar = CMDBAR[variant]
    else:
        app_mod.AbDiffPanel = DIFF[variant]
    app_mod.S19TuiApp().run()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "shot":
        _shot()
    elif len(sys.argv) > 2 and sys.argv[1] in ("cmdbar", "diff"):
        _live(sys.argv[1], sys.argv[2].upper())
    else:
        print(__doc__)
