#!/usr/bin/env python3
"""
THROWAWAY — N8 per-view Legend enrichment, design pass (prototype only).

Question the operator asked: the per-view Legend (N1 already scopes it to the
active screen) should show not just colour codes but a small ANNOTATED EXAMPLE /
mini-construction of the data each view deals with, so the reader learns what
each part means.

This deploys THREE radically-different LAYOUT variants of the enriched Legend
modal body, switchable live (keys 1/2/3, ←/→ cycle), and a `shot` entry that
captures each as an SVG at both C-13 regimes (120-wide and 80-wide). It reuses
the REAL legend data (`LEGEND_TABLE`, `COLOUR_SEVERITY`), the REAL severity
classes (`css_class_for_severity`), and the REAL `styles.tcss` (via CSS_PATH) so
the render is honestly quantized — no mockup lies.

Variants (they disagree on STRUCTURE, not colour):
  A — Example CARD on top, colour key stacked below (single column).
  B — TWO-COLUMN: annotated example | colour key, side by side.
  C — INLINE annotated key: each colour row carries a rendered sample token
      painted in that severity, so the example and the key are one list.

Run:
    python prototypes/legend_n8.prototype.py            # live, switch 1/2/3
    python prototypes/legend_n8.prototype.py shot        # write the SVGs

NOT production code. The winning layout folds into legend.py + screens.py
(LegendScreen) + styles.tcss on the way in, rewritten with tests.
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
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.widgets import Footer, Label, Static

from s19_app.tui.color_policy import css_class_for_severity
from s19_app.tui.legend import COLOUR_SEVERITY, LEGEND_TABLE


# ─────────────────────────────────────────────────────────────────────────────
# N8 CONTENT — the annotated example per view (this is the real content proposal;
# the prototype only decides how to LAY IT OUT). Each entry: a title, the mini
# construction lines, and the label/annotation caption.
# ─────────────────────────────────────────────────────────────────────────────
EXAMPLES: dict[str, dict] = {
    "Workspace": {
        "blurb": "The top “Loaded” panel — one slot per file type:",
        "rows": [
            ("S19", "firmware.s19", "1.2 KB · 3 rng", "image spine (bytes + ranges)"),
            ("MAC", "firmware.mac", "12 records", "symbol→address map"),
            ("A2L", "firmware.a2l", "48 tags", "calibration metadata"),
            ("A2L", "(none)", "", "dim until that file is loaded"),
        ],
        "labels": "kind · filename · summary · what it is",
    },
    "A2L": {
        "blurb": "An A2L tag row — the columns you see in the Explorer:",
        "cells": [("RPM_LIMIT", "name"), ("VALUE", "type"),
                  ("0x80040000", "address"), ("4 B", "length")],
        "note": "Row COLOUR = memory-check result (key below).",
    },
}

# Section order to render in the prototype (Workspace = the NEW section the
# operator specifically called out; A2L = a representative colour-keyed view).
_VIEW_ORDER = ("Workspace", "A2L")


# ── shared example builders ──────────────────────────────────────────────────
def _workspace_example() -> list[Static]:
    ex = EXAMPLES["Workspace"]
    out: list[Static] = [Static(ex["blurb"], classes="n8-blurb")]
    for kind, fname, summ, what in ex["rows"]:
        tail = f"   [dim]← {what}[/dim]"
        summ_txt = f"   {summ}" if summ else ""
        out.append(Static(f"[b]{kind:>3}[/b]  {fname}{summ_txt}{tail}", classes="n8-line"))
    out.append(Static(f"[dim]{ex['labels']}[/dim]", classes="n8-caption"))
    return out


def _a2l_example() -> list[Static]:
    ex = EXAMPLES["A2L"]
    values = "   ".join(f"[b]{v}[/b]" for v, _ in ex["cells"])
    labels = "   ".join(f"[dim]{lab}[/dim]" for _, lab in ex["cells"])
    return [
        Static(ex["blurb"], classes="n8-blurb"),
        Static(values, classes="n8-line"),
        Static(labels, classes="n8-caption"),
        Static(f"[dim]{ex['note']}[/dim]", classes="n8-caption"),
    ]


def _example_block(section: str) -> list[Static]:
    return _workspace_example() if section == "Workspace" else _a2l_example()


def _colour_rows(section: str, *, inline_sample: bool = False) -> list[Label]:
    """The existing colour key for a section, optionally with a rendered sample
    token (Variant C) painted in that severity."""
    table = LEGEND_TABLE.get(section)
    if not table:  # Workspace is example-only — no severity colour key.
        return []
    rows: list[Label] = []
    for classification, (colour, meaning) in table.items():
        sev = COLOUR_SEVERITY.get(colour)
        sev_class = css_class_for_severity(sev) if sev is not None else ""
        classes = f"legend-row {sev_class}".strip()
        if inline_sample:
            sample = {"Red": "RPM ✗ mismatch", "Green": "RPM ✓ present",
                      "White": "RPM valid", "Grey": "RPM  ·  unchecked",
                      "Pale yellow": "RPM ⚠ warning",
                      "Errors": "✗ error", "Warnings": "⚠ warning",
                      "Optional info": "ⓘ info"}.get(classification, classification)
            rows.append(Label(f"{sample:<20} {classification} — {meaning}", classes=classes))
        else:
            rows.append(Label(f"{classification} — {meaning}", classes=classes))
    return rows


# ── the three layout variants ────────────────────────────────────────────────
def variant_a() -> Container:
    """A — example CARD on top, colour key stacked below."""
    blocks: list = []
    for section in _VIEW_ORDER:
        blocks.append(Label(section, classes="legend-artifact"))
        blocks.append(Container(*_example_block(section), classes="n8-card"))
        blocks.extend(_colour_rows(section))
    return ScrollableContainer(*blocks, id="v-A", classes="legend-body-proto")


def variant_b() -> Container:
    """B — two-column: annotated example | colour key."""
    cols: list = []
    for section in _VIEW_ORDER:
        cols.append(Label(section, classes="legend-artifact"))
        left = Vertical(*_example_block(section), classes="n8-col-ex")
        right = Vertical(*_colour_rows(section), classes="n8-col-key")
        cols.append(Horizontal(left, right, classes="n8-two-col"))
    return ScrollableContainer(*cols, id="v-B", classes="legend-body-proto")


def variant_c() -> Container:
    """C — inline annotated key: sample token painted in each severity."""
    blocks: list = []
    for section in _VIEW_ORDER:
        blocks.append(Label(section, classes="legend-artifact"))
        # one construction line for context, then the merged sample+key list
        blocks.append(_example_block(section)[0])  # the blurb only
        blocks.extend(_colour_rows(section, inline_sample=True))
    return ScrollableContainer(*blocks, id="v-C", classes="legend-body-proto")


_VARIANTS = {"A": variant_a, "B": variant_b, "C": variant_c}


class LegendN8Proto(App):
    CSS_PATH = "../s19_app/tui/styles.tcss"
    # Prototype-only styling for the new n8-* classes (folds into styles.tcss on
    # the way in). Kept minimal — the sev-* / legend-* classes come from the real
    # stylesheet so the colours are honestly quantized.
    CSS = """
    #proto_dialog { height: 90%; width: 90%; border: round #91abec;
        background: #0f1525; padding: 1 2; }
    .proto-title { text-style: bold; color: #91abec; }
    .legend-body-proto { height: 1fr; overflow-y: auto; }
    .n8-card { border: round #1b233a; padding: 0 1; margin: 0 0 1 0; height: auto; }
    .n8-blurb { text-style: italic; margin-bottom: 1; }
    .n8-line { height: auto; }
    .n8-caption { color: #969aad; }
    .n8-two-col { height: auto; margin-bottom: 1; }
    .n8-col-ex { width: 1fr; border-right: solid #1b233a; padding-right: 1; }
    .n8-col-key { width: 1fr; padding-left: 1; }
    .hidden { display: none; }
    """
    BINDINGS = [
        ("1", "show('A')", "A: card-on-top"),
        ("2", "show('B')", "B: two-column"),
        ("3", "show('C')", "C: inline"),
        ("right", "cycle(1)", "next"),
        ("left", "cycle(-1)", "prev"),
        ("q", "quit", "quit"),
    ]

    def __init__(self, variant: str = "A") -> None:
        super().__init__()
        self._variant = variant

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Classification legend — N8 example enrichment", classes="proto-title"),
            variant_a(),
            variant_b(),
            variant_c(),
            id="proto_dialog",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.action_show(self._variant)

    def action_show(self, v: str) -> None:
        self._variant = v
        for k in "ABC":
            self.query_one(f"#v-{k}").set_class(k != v, "hidden")

    def action_cycle(self, d: int) -> None:
        self.action_show("ABC"[("ABC".index(self._variant) + d) % 3])


def _shot() -> None:
    import asyncio

    here = Path(__file__).resolve().parent

    async def run(v: str, size: tuple[int, int], tag: str) -> None:
        app = LegendN8Proto(variant=v)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show(v)
            await pilot.pause()
            app.save_screenshot(str(here / f"legend_n8.variant_{v}.{tag}.svg"))

    for v in "ABC":
        asyncio.run(run(v, (120, 40), "120w"))
        asyncio.run(run(v, (80, 30), "80w"))


if __name__ == "__main__":
    _shot() if len(sys.argv) > 1 and sys.argv[1] == "shot" else LegendN8Proto().run()
