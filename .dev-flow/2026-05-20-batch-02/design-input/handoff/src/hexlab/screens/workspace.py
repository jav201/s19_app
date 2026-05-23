"""Direction B — Workspace screen.

Top: command bar.
Body: rail (left) │ main column (memory map strip + hex view) │ inspector (right).
Bottom: status footer (Textual provides this for free via App.BINDINGS).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from hexlab.core import sample_data as S
from hexlab.widgets.command_bar import CommandBar
from hexlab.widgets.hex_view import HexView
from hexlab.widgets.inspector import Inspector
from hexlab.widgets.memory_map import MemoryMap
from hexlab.widgets.rail import Rail, RailItem


class WorkspaceScreen(Screen):
    """The default screen — Direction B."""

    BINDINGS = [
        Binding("slash", "focus_find", "Find"),
        Binding("g", "goto", "Go-to"),
        Binding("1", "rail('ws')",    "Workspace", show=False),
        Binding("2", "rail('a2l')",   "A2L",       show=False),
        Binding("3", "rail('mac')",   "MAC",       show=False),
        Binding("4", "rail('map')",   "Map",       show=False),
        Binding("5", "rail('iss')",   "Issues",    show=False),
        Binding("6", "rail('patch')", "Patch",     show=False),
        Binding("7", "rail('diff')",  "Diff",      show=False),
        Binding("8", "rail('bm')",    "Bookmarks", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield CommandBar(errors=3, warnings=3, coverage=71, crc="0x4C9F2A1B")
        with Horizontal(id="body"):
            yield Rail(active="ws")
            with Vertical(id="main"):
                yield MemoryMap(S.sample_ranges())
                yield HexView(
                    S.sample_hex_rows(0x80000000, count=40),
                    mac_addrs={0x80000004, 0x80000005, 0x80000006, 0x80000007},
                )
            yield Inspector()
        yield Footer()

    # ── Actions ─────────────────────────────────────────────────────────

    def action_focus_find(self) -> None:
        # Placeholder — full impl mounts a Find overlay
        self.app.notify("Find — wire to find overlay")

    def action_goto(self) -> None:
        # Placeholder — full impl prompts for an address
        self.app.notify("Go-to address — wire to GotoModal")

    def action_rail(self, key: str) -> None:
        # Sketch: just notify. Full impl: self.app.push_screen(SCREEN_FOR[key])
        self.app.notify(f"Rail → {key}")

    # ── Events ──────────────────────────────────────────────────────────

    def on_rail_item_selected(self, message: RailItem.Selected) -> None:
        self.action_rail(message.key)
