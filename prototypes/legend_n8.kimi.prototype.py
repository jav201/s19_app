#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THROWAWAY — N8 comprehensive per-view Legend, CARD-on-TOP variant (prototype).

Design proposal for feature N8: the per-view Legend modal (N1 already scopes it
to the active screen) becomes a per-view REFERENCE — for each view it explains
EVERY informational element on screen (every text field, info tile, number,
column, glyph and colour) with a small annotated example CARD on top, then the
colour key below it, single column, scrollable, 120-column regime.

Views covered (keys 1-5, ←/→ to cycle):
  1 Workspace      — example-only card (no severity colour key on this view)
  2 A2L Explorer   — card + real LEGEND_TABLE["A2L"] colour key
  3 Memory Map     — card + real band-* entropy key (NOT a severity domain)
  4 MAC            — card + real LEGEND_TABLE["MAC"] key + the orange3 vs
                     "Pale yellow" reconciliation block
  5 Issues         — card + real LEGEND_TABLE["Issues"] colour key

Honest render: CSS_PATH points at the REAL ../s19_app/tui/styles.tcss, colour
key rows come from the REAL LEGEND_TABLE + COLOUR_SEVERITY +
css_class_for_severity, band rows from the REAL entropy_style.band_style over
the REAL ENTROPY_BANDS ranges. Custom palette vars ($accent-calm etc.) do NOT
resolve inside an inline CSS= block, so n8-* prototype rules use hex literals
(accent #91abec, panel #0f1525, rule #1b233a); the sev-*/band-* classes come
from CSS_PATH.

Copy is sized for 120x40: card inner width ~100 chars, so every line stays
≤ 98 visible chars (no wrapping) and each whole view fits the 36-row dialog
viewport. Exact copy + cut notes: prototypes/legend_n8.kimi.NOTES.md.
Content spec: prototypes/legend_n8.INVENTORY.md.

Run:
    PYTHONUTF8=1 python prototypes/legend_n8.kimi.prototype.py         # live
    PYTHONUTF8=1 python prototypes/legend_n8.kimi.prototype.py shot    # SVGs

NOT production code. No production module is touched.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Windows consoles default to cp1252 — make the block/arrow glyphs safe.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

# Make the package importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.widgets import Footer, Label, Static

from s19_app.tui.color_policy import css_class_for_severity
from s19_app.tui.entropy_style import band_style
from s19_app.tui.legend import COLOUR_SEVERITY, LEGEND_TABLE
from s19_app.tui.services.entropy_service import ENTROPY_BANDS


_VIEW_ORDER = ("Workspace", "A2L Explorer", "Memory Map", "MAC", "Issues")

# DOM-id / filename tokens (view names contain spaces — not valid DOM ids):
# shot writes legend_n8.variant_kimi.<token>.svg
_SHOT_TOKENS = {
    "Workspace": "workspace",
    "A2L Explorer": "a2l",
    "Memory Map": "memory_map",
    "MAC": "mac",
    "Issues": "issues",
}


# ── shared line helpers ──────────────────────────────────────────────────────
def _sub(text: str) -> Static:
    """Sub-heading inside an example card."""
    return Static(text, classes="n8-sub")


def _line(text: str) -> Static:
    """Rendered sample line (Rich markup allowed; literal brackets escaped)."""
    return Static(text, classes="n8-line")


def _cap(text: str) -> Static:
    """Dim annotation/caption line."""
    return Static(text, classes="n8-caption")


# ── per-view annotated example cards ─────────────────────────────────────────
def _workspace_card() -> Container:
    return Container(
        _sub("Memory strip (top) — one glyph per address cell; glyph carries meaning, colour secondary"),
        _line(r"·  ░  ▒  ▓  ╱  █"),
        _cap("· constant/padding (grey)   ░ low—structured/tables (green)   ▒ medium—calibration (amber)"),
        _cap("▓ high/random—code (red)   ╱ gap/unmapped   █ fallback: valid green / invalid red / gap grey"),
        _sub("Loaded panel — one slot per artifact"),
        _line(r"[b]S19[/]  firmware.s19   1.2 KiB · 3 rng   = name · mapped bytes · range count"),
        _line(r"[b]MAC[/]  checks.mac   5 records      [b]A2L[/]  model.a2l   42 tags   = name · count"),
        _cap(r"(none) dim = not loaded · \[u] unload one · \[U] unload all"),
        _sub("Data Sections (left pane) — one row per contiguous range"),
        _line(r"[b]✓ 0x00000000 – 0x000004FF   1.2 KiB ▒[/]"),
        _cap("= ✓/✗ validity · start address · inclusive end · humanized size · dominant band glyph"),
        _cap("green row = valid · red = invalid · █░░░░░░░ 8-cell bar = range size vs largest range"),
        _cap("... N more ranges (see log) ... = over 200 · MAC out-of-range @ 0x… = amber, outside ranges"),
        _sub("Hex view (center pane) — Search ASCII / Goto 0xADDR drive it"),
        _line(r"[b]0x00001000[/]  DE AD BE EF … 00  |.....|"),
        _cap("= row address · 16 byte values (blank = unmapped) · ASCII gutter (. = non-printable)"),
        _sub("Context / coverage stats (right pane)"),
        _line(r"Coverage: 87.50%   Ranges: 3   Errors: 0   Warnings: 2"),
        _cap("= % of image span covered by valid ranges · total ranges · ERROR issues · WARNING issues"),
        _line(r"Loader 0 err · ⚠4 OOO · Entry 0x00000000"),
        _cap("= loader errors (red >0) · out-of-order S19 records (yellow >0) · entry point (— when absent)"),
        _cap("A2L summary lines 1-20 / 142 = right-pane preview · No A2L loaded. = empty"),
        _sub("Status bar (under every screen)"),
        _cap("last action · progress bar · 4 log-tail lines · empty: No file loaded - Ctrl+L (or 'l') / 'p'"),
        classes="n8-card",
    )


def _a2l_card() -> Container:
    return Container(
        _sub("One table row — the 16 Explorer columns (sample values, in two halves)"),
        _line(r"[b]RPM_LIMIT ✓[/]  0x80040000  4  assigned  7500  7500.0  yes  flash"),
        _cap("= Tag(name + ✓ in image / · not) · Address · Length(bytes, n/a) · Source(assigned/formula)"),
        _cap("· Raw(decoded) · Physical(engineering value) · InMem(yes/no/n/a) · Region(flash/ram/unknown)"),
        _line(r"0..8000  rpm  —  MSB_FIRST  no  ENGINE  calibratable  UWORD"),
        _cap("= Limits lo..hi · Unit · Bits mask · Endian · Virt · Func · Access · Dtype"),
        _cap("Access: read_only / calibratable · Dtype: UWORD, FLOAT32_IEEE …"),
        _sub("Summary line"),
        _line(r"Page 2/7 | tags 201-400 / 1394 (page size 200; +/- to change) · 312 in image"),
        _cap("= current page / pages · tag range shown / total · page-size hint · in-image counter (green)"),
        _sub("Filter row"),
        _line(r"\[text]  \[Field: name]  (All | Invalid | In-Memory)  \[Find next]  \[Page Prev/Next]"),
        _cap("text narrows rows · Field targets one column · modes all/invalid/in-image · Find next · paging"),
        _sub("Detail card (selected tag — fields beyond the table)"),
        _cap("desc · unit/conv · layout(RECORD_LAYOUT) · byteorder · limits · display_identifier"),
        _cap("~10 more fields stay in detail/log only (matrix dims, axis meta, decode errors, raw bytes…)"),
        classes="n8-card",
    )


def _memory_map_band_bar() -> Horizontal:
    """Band-bar sample painted through the REAL band-* classes from CSS_PATH."""
    return Horizontal(
        Static("▒" * 12, classes="band-medium n8-seg"),
        Static("▓" * 6, classes="band-high n8-seg"),
        Static("╱" * 3, classes="n8-gap n8-seg"),
        Static("░" * 10, classes="band-low n8-seg"),
        Static("·" * 4, classes="band-constant n8-seg"),
        Static("▓" * 6, classes="band-high n8-seg"),
        classes="n8-bandbar",
    )


def _memory_map_card() -> Container:
    return Container(
        _sub("Header + band bar (one proportional segment per merged run)"),
        _line(r"Entropy bands - 7 region(s), 262144 B mapped"),
        _cap("= merged runs + mapped bytes · empty: No file loaded … / No entropy detail for this image."),
        _memory_map_band_bar(),
        _cap("glyph repeated per segment · ╱╱╱ gap hatch = unmapped gap between runs (NOT a band)"),
        _line(r"80000000      80004000      80008000      8000C000      8000FFFF"),
        _cap("address ruler — 5 ticks at 0/25/50/75/100 % of span (8-hex, no 0x prefix)"),
        _sub("Region row (click to inspect + jump to hex)"),
        _line(r"[b]░ 0x80000000  256 B  ██░░  3 sym  low ↵[/]"),
        _cap("= band glyph · start · size · 4-cell size bar(vs largest) · symbols · band label · ↵ open hex"),
        _sub("At a glance"),
        _line(r"░ low 4 ████ 66%   = per-band histogram: glyph · band · count · 6-cell bar · % of regions"),
        _line(r" ▁▂▅█▇▄▂▁ …"),
        _cap(r'sparkline — 24-col entropy profile, 9-level ramp " ▁▂▃▄▅▆▇█" (0 none → 8 max), band-coloured'),
        _sub("Coverage stats + region inspector"),
        _cap("Coverage: 98.44% · Bytes covered · Valid/Invalid ranges · Gaps · Largest gap · Total issues"),
        _cap("inspector: Status VALID/INVALID/GAP · Cell · Region(+A2L sym) · issues · Size · band · Peek"),
        classes="n8-card",
    )


def _mac_card() -> Container:
    return Container(
        _sub("Coverage strip"),
        _line(r"MAC→S19 1 of 2 █████░░░░░ · A2L↔MAC 3 matches"),
        _cap("= MAC addresses in the image (count + green bar) · A2L↔MAC same-address matches"),
        _sub("One table row — the 8 columns"),
        _line(r"[b]✓ VVT_ENABLE[/]  0x80040000  yes  yes  OK  12  —  MEAS:VVT_ENABLE"),
        _cap("= Tag(glyph+name) · Address · InA2L · InMem · Status · SourceLine(.mac) · ParseErr · A2LMatch"),
        _sub("Tag status glyphs (glyph is the primary cue)"),
        _line(r"✗ parse error(red) · ⚠ out-of-image(orange) · ✓ in image(green) · · not checked(grey)"),
        _cap("MAC-only / no primary image stays grey — deliberately NOT green"),
        _sub("Status vocabulary → row colour"),
        _cap("ERR_PARSE / A2L_ADDR_MISMATCH / NO_ADDR = error(red) · NOT_IN_A2L = warning"),
        _cap("OUT_OF_IMAGE = info(white) · NO_A2L = neutral(grey) · OK = green"),
        classes="n8-card",
    )


def _issues_card() -> Container:
    return Container(
        _sub("Severity strip — whole-list distribution + 5-cell bars (red / pale yellow / cyan)"),
        _line(r"Errors 3 ███░░   Warnings 1 █░░░░   Info 2 ██░░░"),
        _sub("Filter row"),
        _line(r"(All | Errors | Warnings)  \[Legend]   — Info rows appear only under All"),
        _sub("Grouped list (order ERROR → WARNING → INFO)"),
        _line(r"[b]✗ ERRORS (3)[/]"),
        _line(r"   TRIPLE_NAME_ADDRESS_MISMATCH   VVT_ENABLE · 0x80040000 · addresses differ   a2l, mac, s19"),
        _cap("= code chip · detail(symbol · 0xADDR · message) · related artifacts · ⚠/• head W/I groups"),
        _sub("The 17 issue codes, by family (E = error, W = warning)"),
        _cap("MAC: PARSE_ERROR · EMPTY_NAME · INVALID_ADDRESS · DUPLICATE_NAME (E) DUPLICATE_ADDRESS (E/W/I)"),
        _cap("A2L: STRUCTURE_ERROR·INVALID_ADDRESS·DUPLICATE_SYMBOL(E) UNRECOGNIZED_BLOCK·BROKEN_REFERENCE(W)"),
        _cap("CROSS: MAC_S19 / A2L_S19 OUT_OF_RANGE + OVERLAP_AMBIGUOUS (W) · MAC / A2L_ONLY_SYMBOL (W)"),
        _cap("TRIPLE_NAME_ADDRESS_MISMATCH (E)"),
        _sub("Summary + Hex Peek"),
        _line(r"total=6 | errors=3 | warnings=1 | info=2 | filter=all | page 1/1 rows 1-6/6"),
        _cap("Hex Peek — ±6 hex rows around the selected issue's address · (issue has no address …)"),
        classes="n8-card",
    )


_CARDS = {
    "Workspace": _workspace_card,
    "A2L Explorer": _a2l_card,
    "Memory Map": _memory_map_card,
    "MAC": _mac_card,
    "Issues": _issues_card,
}

# Colour-key section in LEGEND_TABLE per view (Workspace = example-only,
# Memory Map = band key instead of a severity key).
_KEY_SECTION = {"A2L Explorer": "A2L", "MAC": "MAC", "Issues": "Issues"}


def _colour_rows(section: str) -> list[Static]:
    """The REAL colour key for a section — same data/classes as LegendScreen,
    but Static (wraps) instead of Label (truncates at the viewport width)."""
    rows: list[Static] = []
    for classification, (colour, meaning) in LEGEND_TABLE[section].items():
        sev = COLOUR_SEVERITY.get(colour)
        sev_class = css_class_for_severity(sev) if sev is not None else ""
        classes = f"legend-row {sev_class}".strip()
        rows.append(Static(f"{classification} — {meaning}", classes=classes))
    return rows


def _band_rows() -> list:
    """Memory-Map band key — REAL band-* classes, ranges from ENTROPY_BANDS."""
    rows: list = []
    last = len(ENTROPY_BANDS) - 1
    for i, (label, lo, hi) in enumerate(ENTROPY_BANDS):
        cls, glyph, meaning = band_style(label)
        hi_txt = "8" if label == "high/random" else f"{hi:g}"
        close = "]" if i == last else ")"
        rows.append(
            Static(
                rf"{glyph} {label} \[{lo:g},{hi_txt}{close} — {meaning}",
                classes=f"legend-row {cls}",
            )
        )
    rows.append(
        Static(
            "╱ gap hatch — unmapped gap between runs (NOT a band, no colour class)",
            classes="legend-row n8-gap",
        )
    )
    rows.append(
        _cap(
            "bands = bits/byte entropy over a 256 B window; boundary values go to the HIGHER band. "
            "Bands ≠ severities: an ENTROPY domain, separate from the sev-* severity domain."
        )
    )
    return rows


def _mac_reconciliation() -> list:
    """The MAC inline-orange3 vs legend-word 'Pale yellow' gotcha, shown honestly."""
    return [
        _cap("⚠ ORANGE vs Pale yellow — the key names the SEVERITY (.sev-warning #f6ff8f, cross-view lists)"),
        _line(r"[b #d9a35b]⚠ VVT_TEMP  0x80041234  yes  no  NOT_IN_A2L  17[/]   ← what a warning row looks like"),
        _cap("the MAC DataTable paints INLINE styles — a warning row renders orange (the MAC cue: ⚠ glyph,"),
        _cap("hex MAC overlay, Sections labels). Two pipelines, one severity — trust glyph + Status not hue."),
    ]


def _view_body(view: str) -> ScrollableContainer:
    blocks: list = [_CARDS[view]()]
    key = _KEY_SECTION.get(view)
    if key is not None:
        blocks.append(Label("Colour key — row colours", classes="legend-artifact"))
        blocks.extend(_colour_rows(key))
    elif view == "Memory Map":
        blocks.append(Label("Band key — entropy colours (NOT severities)", classes="legend-artifact"))
        blocks.extend(_band_rows())
    else:
        blocks.append(
            _cap("(this view has no severity colour key — its cues are the glyphs and labels above)")
        )
    if view == "MAC":
        blocks.extend(_mac_reconciliation())
    return ScrollableContainer(
        *blocks, id=f"v-{_SHOT_TOKENS[view]}", classes="legend-body-proto"
    )


class LegendN8Kimi(App):
    CSS_PATH = "../s19_app/tui/styles.tcss"
    # Prototype-only styling for the n8-* classes. Hex literals only — custom
    # vars like $accent-calm do NOT resolve inside an inline CSS= block.
    CSS = """
    #proto_dialog { height: 90%; width: 90%; border: round #91abec;
        background: #0f1525; padding: 1 2; }
    .proto-title { text-style: bold; color: #91abec; }
    .legend-body-proto { height: 1fr; overflow-y: auto; }
    .n8-card { border: round #1b233a; padding: 0 1; margin: 0 0 1 0; height: auto; }
    .n8-sub { text-style: bold; color: #91abec; }
    .n8-line { height: auto; }
    .n8-caption { color: #969aad; height: auto; }
    .n8-bandbar { height: 1; }
    .n8-seg { width: auto; height: 1; }
    .n8-gap { color: #969aad; }
    .hidden { display: none; }
    """
    BINDINGS = [
        ("1", "show_view('Workspace')", "Workspace"),
        ("2", "show_view('A2L Explorer')", "A2L"),
        ("3", "show_view('Memory Map')", "Map"),
        ("4", "show_view('MAC')", "MAC"),
        ("5", "show_view('Issues')", "Issues"),
        ("right", "cycle_view(1)", "next"),
        ("left", "cycle_view(-1)", "prev"),
        ("q", "quit", "quit"),
    ]

    def __init__(self, view: str = "Workspace") -> None:
        super().__init__()
        self._view = view

    def compose(self) -> ComposeResult:
        yield Container(
            Label("", classes="proto-title", id="proto_title"),
            *(_view_body(v) for v in _VIEW_ORDER),
            id="proto_dialog",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.action_show_view(self._view)

    def action_show_view(self, view: str) -> None:
        self._view = view
        self.query_one("#proto_title", Label).update(
            f"N8 legend — {view}   (1-5 / ←→ to switch views)"
        )
        for v in _VIEW_ORDER:
            self.query_one(f"#v-{_SHOT_TOKENS[v]}").set_class(v != view, "hidden")

    def action_cycle_view(self, d: int) -> None:
        i = (_VIEW_ORDER.index(self._view) + d) % len(_VIEW_ORDER)
        self.action_show_view(_VIEW_ORDER[i])


def _shot() -> None:
    import asyncio

    here = Path(__file__).resolve().parent

    async def run(view: str) -> None:
        app = LegendN8Kimi(view=view)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_view(view)
            await pilot.pause()
            out = here / f"legend_n8.variant_kimi.{_SHOT_TOKENS[view]}.svg"
            app.save_screenshot(str(out))
            print(f"wrote {out.name} ({out.stat().st_size} bytes)")

    for view in _VIEW_ORDER:
        asyncio.run(run(view))


if __name__ == "__main__":
    _shot() if len(sys.argv) > 1 and sys.argv[1] == "shot" else LegendN8Kimi().run()
