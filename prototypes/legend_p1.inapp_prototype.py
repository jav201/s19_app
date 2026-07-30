#!/usr/bin/env python
"""THROWAWAY in-APP prototype — P1 Legend-modal reorganization (2026-07-30).

Three LegendScreen variants mounted INSIDE the real S19TuiApp (sub-shape A). All three
REUSE the shipped data pipeline verbatim — ``_render_card`` / ``_render_key`` (so the
map band-key branch and the ``#legend_mac_warning_sample`` inline-orange row keep
working) — and only reorganize the layout (see p1_design_defects.NOTES.md §5):

  A — Tabbed:          one TabPane per ROLE_SUB card section + a final `Key` tab.
  B — Two-pane:        card left (3fr) | colour key right (2fr), independent scrolls.
  C — Key-first:       colour key pinned on top; card sections as Collapsibles.

Run live:   python prototypes/legend_p1.inapp_prototype.py A|B|C   (press k on any view)
Screenshot: python prototypes/legend_p1.inapp_prototype.py shot
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.widget import Widget
from textual.widgets import Button, Collapsible, Label, Static, TabbedContent, TabPane

from s19_app.tui import app as app_mod
from s19_app.tui.legend import LEGEND_EXAMPLES, ROLE_SUB
from s19_app.tui.screens import LegendScreen


def _section_title(text: str) -> str:
    """Compress a ROLE_SUB heading into a short tab/collapsible title."""
    head = text.split(" — ")[0].split("(")[0].strip()
    words = head.split()
    title = ""
    for word in words:
        candidate = f"{title} {word}".strip()
        if len(candidate) > 18 and title:
            break
        title = candidate
    return title or head[:18]


def _card_sections(screen: LegendScreen) -> List[Tuple[str, List[Widget]]]:
    """Split the shipped card widgets into (title, widgets) per ROLE_SUB heading.

    The widgets come from the PARENT's ``_render_card`` (reuse, no fork); the
    grouping walks the source ``LEGEND_EXAMPLES`` lines in parallel — the two
    sequences are 1:1 by construction.
    """
    lines = LEGEND_EXAMPLES.get(screen._view_key, []) if screen._view_key else []
    widgets = screen._render_card()
    sections: List[Tuple[str, List[Widget]]] = []
    current_title = "Legend"
    current: List[Widget] = []
    for line, widget in zip(lines, widgets):
        if line.role == ROLE_SUB:
            if current:
                sections.append((current_title, current))
            current_title = _section_title(line.text)
            current = [widget]
        else:
            current.append(widget)
    if current:
        sections.append((current_title, current))
    return sections


class VariantALegend(LegendScreen):
    """A — Tabbed: shallow pages instead of one deep scroll."""

    DEFAULT_CSS = """
    VariantALegend TabPane { padding: 1 1 0 1; }
    """

    def compose(self):
        sections = _card_sections(self)
        key_widgets = self._render_key()
        with Container(id="legend_dialog", classes="modal-dialog"):
            yield Label("Classification legend", classes="modal-title")
            if sections or key_widgets:
                with TabbedContent():
                    for title, widgets in sections:
                        with TabPane(title):
                            yield ScrollableContainer(*widgets)
                    if key_widgets:
                        with TabPane("Key"):
                            yield ScrollableContainer(*key_widgets)
            with Container(id="legend_buttons", classes="modal-buttons"):
                yield Button("Close", id="legend_close", classes="modal-confirm")


class VariantBLegend(LegendScreen):
    """B — Two-pane: the key is always on screen beside the card."""

    DEFAULT_CSS = """
    VariantBLegend #legend_dialog { width: 96%; }
    VariantBLegend #proto_split { height: 1fr; }
    VariantBLegend #proto_card_pane {
        width: 3fr; height: 100%; padding-right: 1;
        border-right: solid #1b233a;
    }
    VariantBLegend #proto_key_pane { width: 2fr; height: 100%; padding-left: 1; }
    VariantBLegend #proto_key_head { text-style: bold; margin-bottom: 1; }
    """

    def compose(self):
        card = self._render_card()
        key = self._render_key()
        key_pane: List[Widget] = [Static("Colour key", id="proto_key_head")]
        key_pane.extend(key if key else [Static("(this view keys by example only)")])
        yield Container(
            Label("Classification legend", classes="modal-title"),
            Horizontal(
                ScrollableContainer(*card, id="proto_card_pane"),
                ScrollableContainer(*key_pane, id="proto_key_pane"),
                id="proto_split",
            ),
            Container(
                Button("Close", id="legend_close", classes="modal-confirm"),
                id="legend_buttons",
                classes="modal-buttons",
            ),
            id="legend_dialog",
            classes="modal-dialog",
        )


class VariantCLegend(LegendScreen):
    """C — Key-first outline: the reference answer on top, examples on demand."""

    DEFAULT_CSS = """
    VariantCLegend #proto_key_top { height: auto; max-height: 50%; overflow-y: auto; padding-bottom: 1; }
    VariantCLegend #proto_outline { height: 1fr; }
    VariantCLegend Collapsible { border: none; background: #0f1525; }
    """

    def compose(self):
        key = self._render_key()
        sections = _card_sections(self)
        collapsibles = [
            Collapsible(*widgets, title=title, collapsed=(index > 0))
            for index, (title, widgets) in enumerate(sections)
        ]
        body: List[Widget] = []
        if key:
            body.append(Vertical(*key, id="proto_key_top"))
        body.append(ScrollableContainer(*collapsibles, id="proto_outline"))
        yield Container(
            Label("Classification legend", classes="modal-title"),
            *body,
            Container(
                Button("Close", id="legend_close", classes="modal-confirm"),
                id="legend_buttons",
                classes="modal-buttons",
            ),
            id="legend_dialog",
            classes="modal-dialog",
        )


_VARIANTS: dict[str, type[LegendScreen]] = {
    "A": VariantALegend,
    "B": VariantBLegend,
    "C": VariantCLegend,
}

#: view_key -> sections, resolved exactly the way action_show_legend does.
_SHOT_VIEWS = ("workspace", "mac")


def _shot() -> None:
    import asyncio

    here = Path(__file__).resolve().parent

    async def run(variant: str) -> None:
        cls = _VARIANTS[variant]
        sections_map = app_mod.S19TuiApp._SCREEN_LEGEND_SECTIONS

        app = app_mod.S19TuiApp()
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for view in _SHOT_VIEWS:
                app.push_screen(cls(sections=sections_map.get(view), view_key=view))
                await pilot.pause(); await pilot.pause()
                app.save_screenshot(
                    str(here / f"legend_p1.variant_{variant}.{view}.120x30.svg")
                )
                app.pop_screen()
                await pilot.pause()

        app = app_mod.S19TuiApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.push_screen(cls(sections=sections_map.get("mac"), view_key="mac"))
            await pilot.pause(); await pilot.pause()
            app.save_screenshot(
                str(here / f"legend_p1.variant_{variant}.mac.80x24.svg")
            )

        # 160x44 high-density pass.
        app = app_mod.S19TuiApp()
        async with app.run_test(size=(160, 44)) as pilot:
            await pilot.pause()
            for view in _SHOT_VIEWS:
                app.push_screen(cls(sections=sections_map.get(view), view_key=view))
                await pilot.pause(); await pilot.pause()
                app.save_screenshot(
                    str(here / f"legend_p1.variant_{variant}.{view}.160x44.svg")
                )
                app.pop_screen()
                await pilot.pause()

    for variant in _VARIANTS:
        asyncio.run(run(variant))
        print(f"variant {variant}: wrote {len(_SHOT_VIEWS) + 1} SVGs")


if __name__ == "__main__":
    arg = sys.argv[1].upper() if len(sys.argv) > 1 else "A"
    if arg == "SHOT":
        _shot()
    else:
        app_mod.LegendScreen = _VARIANTS.get(arg, VariantALegend)
        app_mod.S19TuiApp().run()
