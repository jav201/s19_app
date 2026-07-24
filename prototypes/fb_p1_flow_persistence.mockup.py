# -*- coding: utf-8 -*-
"""PROTOTYPE (throwaway) — FB-P1 visual mockup + SVG export + viz.html builder.

Run:  python prototypes/fb_p1_flow_persistence.mockup.py

Renders REAL Textual screens (a Static-based mockup of the proposed
FlowBuilderPanel Save/Load/Import surfaces — no logic, visuals only) via
`App.run_test` + `export_screenshot`, then inlines the pixel-perfect SVGs into
the Artifact-ready fragment `prototypes/fb_p1_flow_persistence.viz.html`
(inline CSS + inline SVG only, no JS, no external refs — @font-face CDN blocks
emitted by rich's SVG template are stripped).

Surfaces x sizes: (panel, save-modal, load-modal, quarantine) x (80x24, 120x30).
NOT production code; nothing under s19_app/ is imported or touched.
"""

from __future__ import annotations

import asyncio
import html as html_mod
import os
import re
import sys
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

HERE = Path(__file__).resolve().parent
TARGET = HERE / "fb_p1_flow_persistence.viz.html"

# Calm-Dark palette (operator-fixed hex values)
BG = "#0a0e1b"
PANEL = "#0f1525"
ACCENT = "#91abec"
FG = "#e9e9e9"
RULE = "#1b233a"
ODD = "#131a2c"
ERR = "#fd8383"
WARN = "#f6ff8f"
OK = "#54efae"
INFO = "#7dd3fc"
NEUTRAL = "#969aad"


def _strip(*parts: tuple[str, str]) -> Text:
    return Text.assemble(*parts)


def _name_strip(saved: bool) -> Text:
    if saved:
        return _strip(("Flow: ", NEUTRAL), ("nightly-release ", FG),
                      ("✓ saved flows/NightlyRelease.json", OK),
                      ("  · 5 blocks · schema v1", NEUTRAL))
    return _strip(("Flow: ", NEUTRAL), ("nightly-release ", FG),
                  ("● unsaved changes", WARN))


_BLOCK_ROWS = [
    ("1.", "source", "prg.s19", ""),
    ("2.", "patch", "calib_patch.json", ""),
    ("3.", "check", "post_checks.json", "  · block-own-op"),
    ("4.", "crc", "crc32_blocks.json", ""),
    ("5.", "write", "prg_patched.s19", ""),
]


class MockApp(App):
    """One surface per run: panel | save | load | quarantine."""

    CSS = f"""
    Screen {{ background: {BG}; color: {FG}; }}
    #screen {{
        border: round {RULE}; border-title-color: {ACCENT};
        background: {PANEL}; padding: 0 1; height: auto;
    }}
    .dim {{ color: {NEUTRAL}; }}
    #addrow {{ height: 3; margin-top: 1; }}
    .inbox {{
        border: round {RULE}; border-title-color: {NEUTRAL};
        height: 3; padding: 0 1; margin-right: 1;
    }}
    #kind {{ width: 20; }}
    #gating {{ width: 14; }}
    #ref {{ width: 1fr; border: round {ACCENT}; border-title-color: {ACCENT}; }}
    .btn {{
        background: {RULE}; color: {FG}; padding: 0 1;
        width: auto; height: 1; margin-right: 1;
    }}
    .btnp {{
        background: {ACCENT}; color: {BG}; text-style: bold;
        padding: 0 1; width: auto; height: 1; margin-right: 1;
    }}
    #addbtn {{ margin-top: 1; }}
    #blocks {{ height: auto; margin-top: 1; }}
    #blocks Static {{ width: 100%; }}
    .odd {{ background: {ODD}; }}
    #runrow {{ height: 1; margin-top: 1; }}
    #runhint {{ color: {NEUTRAL}; padding: 0 1; }}
    #result {{
        border: round {RULE}; border-title-color: {NEUTRAL};
        margin-top: 1; height: auto; padding: 0 1;
    }}
    #result.quarantine {{
        border: round {ERR}; border-title-color: {ERR};
    }}
    ModalScreen {{ align: center middle; background: {BG} 65%; }}
    #dlg {{
        border: round {ACCENT}; border-title-color: {ACCENT};
        background: {PANEL}; padding: 1 2; width: auto; height: auto;
    }}
    #dlg .inbox {{ margin-right: 0; }}
    #namebox {{ width: 42; border: round {ACCENT}; }}
    #flowlist {{ border: round {RULE}; width: 48; height: auto; padding: 0 1; }}
    #flowlist Static {{ width: 100%; }}
    .sel {{ background: {RULE}; color: {ACCENT}; }}
    #dlg Horizontal {{ height: 1; margin-top: 1; }}
    #dlg .note {{ color: {NEUTRAL}; }}
    """

    def __init__(self, surface: str, wide: bool) -> None:
        super().__init__()
        self.surface = surface
        self.wide = wide

    def compose(self) -> ComposeResult:
        quarantine = self.surface == "quarantine"
        saved_strip = self.wide and self.surface == "panel"
        with Container(id="screen"):
            yield Static(_name_strip(saved_strip), id="strip")
            yield Static(
                "Pick a block kind, enter its project-relative ref, Add; "
                "then Run.", classes="dim")
            with Horizontal(id="addrow"):
                kind = Static(
                    _strip(("Check (list) ", FG), ("▾", ACCENT)), id="kind",
                    classes="inbox")
                kind.border_title = "kind"
                yield kind
                if self.wide:
                    gating = Static(
                        _strip(("advisory ", FG), ("▾", ACCENT)), id="gating",
                        classes="inbox")
                    gating.border_title = "gating"
                    yield gating
                ref = Static(
                    _strip(("post_checks.json", FG), ("▌", ACCENT)), id="ref",
                    classes="inbox")
                ref.border_title = "ref"
                yield ref
                yield Static(" Add ", classes="btn", id="addbtn")
            with Vertical(id="blocks"):
                for i, (n, kind_s, ref_s, extra) in enumerate(_BLOCK_ROWS):
                    row = _strip((f" {n} ", NEUTRAL),
                                 (kind_s.ljust(7), INFO), (" ", FG),
                                 (ref_s, FG), (extra, NEUTRAL))
                    yield Static(row, classes="odd" if i % 2 else "")
            with Horizontal(id="runrow"):
                yield Static(" Run ", classes="btnp")
                yield Static(" Clear ", classes="btn")
                yield Static(" Save… ", classes="btn")
                yield Static(" Load… ", classes="btn")
                yield Static("S save · L load (proposed keys)", id="runhint")
            with Vertical(id="result") as result:
                result.border_title = (
                    "result — quarantine" if quarantine else "result")
                if quarantine:
                    result.add_class("quarantine")
                    yield Static(_strip(
                        ("✗ LOAD REJECTED — flows/vendor_flow.json "
                         "(2 findings)", ERR)))
                    yield Static(_strip(
                        ("[MANIFEST-PATH-ESCAPE] ", f"bold {ERR}"),
                        ("blocks[3].config_ref entry escapes the project "
                         "directory -", FG)))
                    yield Static(_strip(
                        ("  entry skipped: '../../other_project/"
                         "secrets.json'", FG)))
                    yield Static(_strip(
                        ("[FLOW-UNKNOWN-KIND]   ", f"bold {ERR}"),
                        ("blocks[5] has unknown kind 'shell'", FG)))
                    yield Static(_strip(
                        ("✓ current flow unchanged — nothing was mounted",
                         OK)))
                else:
                    yield Static(_strip(("✓ FLOW OK — 5 blocks clean", OK)))
                    yield Static(_strip(
                        ("✓ ", OK), ("source    loaded prg.s19 (2 ranges)",
                                     FG)))
                    yield Static(_strip(
                        ("✓ ", OK), ("crc       injected 1 CRC region", FG)))
                    rib = "▪" * 30 + "·" * 10 + "▪" * 4
                    if self.wide:
                        rib = "▪" * 60 + "·" * 20 + "▪" * 8
                    yield Static(_strip((rib, INFO)))
                    yield Static(_strip(
                        ("0x8000-0x8FFF · 0x9100-0x9103 ", NEUTRAL),
                        ("(grown by CRC)", INFO)))
                    yield Static(_strip(("→ wrote prg_patched.s19", OK)))

    def on_mount(self) -> None:
        self.query_one("#screen").border_title = "Flow Builder · rail 8"
        if self.surface == "save":
            self.push_screen(SaveModal())
        elif self.surface == "load":
            self.push_screen(LoadModal())


class SaveModal(ModalScreen):
    def compose(self) -> ComposeResult:
        with Container(id="dlg") as dlg:
            dlg.border_title = "Save flow"
            yield Static("Flow name (flows/<name>.json):")
            name = Static(
                _strip(("NightlyRelease", FG), ("▌", ACCENT)),
                id="namebox", classes="inbox")
            yield name
            yield Static("letters, numbers, - _", classes="note")
            yield Static(_strip(
                ("⚠ overwrites existing NightlyRelease.json", WARN)))
            with Horizontal():
                yield Static(" Save ", classes="btnp")
                yield Static(" Cancel ", classes="btn")


class LoadModal(ModalScreen):
    def compose(self) -> ComposeResult:
        with Container(id="dlg") as dlg:
            dlg.border_title = "Load flow"
            yield Static("Saved flows — protoproj:")
            with Vertical(id="flowlist"):
                yield Static(_strip(("  NightlyRelease", FG)))
                yield Static(_strip(
                    ("▸ vendor_flow", ACCENT),
                    ("                    (imported)", INFO)), classes="sel")
                yield Static(_strip(("  smoke_check", FG)))
            yield Static("Import… copies an external flow.json into flows/",
                         classes="note")
            yield Static("first — never loaded in place.", classes="note")
            with Horizontal():
                yield Static(" Load ", classes="btnp")
                yield Static(" Import… ", classes="btn")
                yield Static(" Cancel ", classes="btn")


# ---------------------------------------------------------------------------
# Export + build
# ---------------------------------------------------------------------------

async def _measure(surface: str, width: int) -> int:
    """Full content height of the mockup screen (#screen is height:auto)."""
    app = MockApp(surface, wide=width >= 120)
    async with app.run_test(size=(width, 80)) as pilot:
        await pilot.pause()
        await pilot.pause()
        return app.query_one("#screen").outer_size.height


async def _export(surface: str, width: int, floor_h: int,
                  title: str) -> tuple[str, int]:
    """Export the surface at its FULL content height (>= the regime floor).

    Returns (svg, rows_captured) — the SVG contains the ENTIRE screen
    top-to-bottom, never just the first viewport.
    """
    full_h = max(await _measure(surface, width), floor_h)
    app = MockApp(surface, wide=width >= 120)
    async with app.run_test(size=(width, full_h)) as pilot:
        await pilot.pause()
        await pilot.pause()
        return app.export_screenshot(title=title), full_h


def _clean_svg(svg: str) -> str:
    """Strip rich's @font-face CDN blocks so the file has NO external refs."""
    svg = re.sub(r"@font-face\s*\{[^}]*\}", "", svg)
    # xmlns namespace URIs are identifiers, not fetches; forbid real refs only.
    assert "url(http" not in svg and 'href="http' not in svg, \
        "external ref survived in SVG"
    return svg


SURFACES = [
    ("s1", "1 · FlowBuilderPanel — name strip + Save/Load row",
     "The dirty glyph ● (warning yellow) marks unsaved edits; after a save it "
     "becomes ✓ and, in the 120-col regime, the strip absorbs the saved-path "
     "detail inline. Save… / Load… join the existing Run/Clear row. Glyph "
     "carries the state; colour is the secondary cue (C-10).", "panel"),
    ("s2", "2 · Save modal (unified Save / Save-As)",
     "One modal: the name field is prefilled with the current name, so "
     "editing the prefill IS Save-As. Name passes sanitize_project_name "
     "(hint line); a live ⚠ notice appears when flows/<name>.json already "
     "exists. Shared .modal-dialog chrome over the dimmed panel.", "save"),
    ("s3", "3 · Load modal — saved flows + Import…",
     "ListView of flows/*.json stems (LoadProjectScreen pattern); the "
     "highlighted row uses the rule-tone selection bar with accent text. "
     "Import… opens the OS file picker and COPIES the external file into "
     "flows/ via copy_into_workarea (containment + dedup) — it is never "
     "loaded in place.", "load"),
    ("s4", "4 · Quarantine card — the rejection surface (signature element)",
     "A rejected flow.json renders its findings as a bordered sev-error card "
     "in #flow_result: the finding codes lead each line, every file-derived "
     "string is markup-safe, and the blocks list above stays INTACT — the ✓ "
     "line states that nothing was mounted. Fail closed, visibly.",
     "quarantine"),
]

CSS = """
.fbp1-page{background:#0a0e1b;color:#e9e9e9;
  font:14px/1.55 ui-sans-serif,system-ui,"Segoe UI",sans-serif;
  padding:28px 20px 60px;max-width:1150px;margin:0 auto;
  overflow-x:clip;overflow-wrap:anywhere}
.fbp1-page h1{font-size:20px;color:#91abec;margin:0 0 4px}
.fbp1-page .sub{color:#969aad;font-size:13px;margin-bottom:22px}
.fbp1-page h2{font-size:15px;color:#e9e9e9;margin:34px 0 4px;
  border-left:3px solid #91abec;padding-left:8px}
.fbp1-page .desc{color:#969aad;font-size:13px;max-width:900px;
  margin-bottom:12px}
.fbp1-page .legend{display:flex;flex-wrap:wrap;gap:10px 18px;
  background:#0f1525;border:1px solid #1b233a;border-radius:6px;
  padding:10px 14px;font-size:12.5px}
.fbp1-page .legend b{color:#e9e9e9;font-weight:600}
.fbp1-page .sw{display:inline-block;width:10px;height:10px;border-radius:2px;
  margin-right:5px;vertical-align:-1px}
.fbp1-page .frame{margin:14px 0;border:1px solid #1b233a;border-radius:6px;
  background:#0f1525;max-width:100%;overflow:hidden}
.fbp1-page .frame .bar{display:flex;justify-content:space-between;
  align-items:center;background:#131a2c;border-bottom:1px solid #1b233a;
  padding:5px 12px;font-size:12px;color:#969aad}
.fbp1-page .frame .bar .size{color:#91abec;
  font-family:ui-monospace,Consolas,monospace}
.fbp1-page .scroll{overflow:auto;max-width:100%;max-height:78vh;padding:6px}
.fbp1-page .scroll svg{display:block;min-width:900px}
.fbp1-page footer{margin-top:40px;color:#969aad;font-size:12px;
  border-top:1px solid #1b233a;padding-top:12px}
"""

LEGEND = """
<div class="legend">
  <span><b>Palette (app-real Calm-Dark)</b></span>
  <span><span class="sw" style="background:#91abec"></span>accent / focus #91abec</span>
  <span><span class="sw" style="background:#fd8383"></span>sev-error #fd8383</span>
  <span><span class="sw" style="background:#f6ff8f"></span>sev-warning #f6ff8f</span>
  <span><span class="sw" style="background:#54efae"></span>sev-ok #54efae</span>
  <span><span class="sw" style="background:#7dd3fc"></span>sev-info #7dd3fc</span>
  <span><span class="sw" style="background:#969aad"></span>neutral #969aad</span>
  <span><span class="sw" style="background:#1b233a;border:1px solid #2a3554"></span>rule/border #1b233a</span>
  <span><b>Glyphs (primary cue, C-10):</b>&nbsp; ● dirty · ✓ saved/ok ·
  ✗ rejected · ⚠ overwrite · ▸ selection · ▪/· ribbon</span>
</div>
"""


def main() -> int:
    os.environ.pop("NO_COLOR", None)
    frames: list[tuple[str, str, str, list[tuple[str, str]]]] = []
    for sid, title, desc, surface in SURFACES:
        rendered: list[tuple[str, str]] = []
        for width, floor_h, label in [(80, 24, "80-col floor regime"),
                                      (120, 30, "120-col regime")]:
            svg, rows = asyncio.run(_export(
                surface, width, floor_h,
                f"s19tui — {title.split('·', 1)[1].strip()}"))
            rendered.append(
                (f"{label} · {width}×{rows} (full height, scroll inside)",
                 _clean_svg(svg)))
        frames.append((sid, title, desc, rendered))

    parts = [
        "<title>FB-P1 flow.json persistence — Save/Load/Import UI design "
        "(to-scale)</title>",
        f"<style>{CSS}</style>",
        '<div class="fbp1-page">',
        "<h1>FB-P1 (batch-53) — Save / Load / Import UI design, to scale"
        "</h1>",
        '<div class="sub">s19_app Flow Builder (rail 8) · every frame is a '
        "REAL Textual screen render (pixel-perfect SVG export) captured at "
        "FULL content height for the 80-col and 120-col regimes, in the "
        "app's real Calm-Dark palette · design source: "
        "prototypes/fb_p1_flow_persistence.NOTES.md · scroll INSIDE each "
        "frame (vertically and horizontally) to see the whole screen</div>",
        LEGEND,
    ]
    for sid, title, desc, rendered in frames:
        parts.append(f'<h2 id="{sid}">{html_mod.escape(title)}</h2>')
        parts.append(f'<div class="desc">{html_mod.escape(desc)}</div>')
        for label, svg in rendered:
            parts.append(
                '<div class="frame"><div class="bar">'
                f"<span>{html_mod.escape(title.split('·', 1)[1].strip())}"
                "</span>"
                f'<span class="size">{label}</span></div>'
                f'<div class="scroll">{svg}</div></div>')
    parts.append(
        "<footer>PROTOTYPE visualization — throwaway design artifact for "
        "FB-P1 (batch-53), rendered from the throwaway Textual mockup "
        "fb_p1_flow_persistence.mockup.py. No production file reflects this "
        "yet; loader semantics proven in fb_p1_flow_persistence.prototype.py "
        "(ALL CASES HELD).</footer>")
    parts.append("</div>")

    doc = "\n".join(parts)
    # Artifact-ready fragment checks
    assert "<!DOCTYPE" not in doc and "<html" not in doc \
        and "<head" not in doc and "<body" not in doc
    assert "<script" not in doc, "zero JS by design"
    assert "url(http" not in doc and 'href="http' not in doc \
        and "src=" not in doc, "no external refs"
    assert doc.count("<svg") == 8, f"expected 8 SVGs, got {doc.count('<svg')}"
    TARGET.write_text(doc, encoding="utf-8")
    print(f"OK wrote {TARGET} ({len(doc)} bytes, 8 inline SVG frames)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
