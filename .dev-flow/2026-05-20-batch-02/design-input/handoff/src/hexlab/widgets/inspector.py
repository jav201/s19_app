"""Right-side context inspector.

Shows the currently-focused thing: byte / range / symbol. In the sketch it
just renders a static layout that mirrors the mock — the full impl would
listen for selection events from `HexView` / outline list and re-render.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import Static


class Inspector(Widget):
    DEFAULT_CSS = """
    Inspector {
        width: 40;
        background: $bg-1;
        border-left: solid $rule;
        padding: 1 2;
    }
    Inspector .h { color: $fg-faint; text-style: bold; padding-bottom: 1; }
    Inspector .k { color: $fg-faint; }
    Inspector .v { color: $fg; }
    Inspector .accent { color: $accent; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("INSPECTOR", classes="h")
            yield Static("[bold]0x80004000[/]  reset entry", classes="v")
            yield Static("range: [yellow]Reset vectors[/]  · code", classes="v")
            yield Static("")
            yield Static("BYTES", classes="h")
            yield Static("[dim]u8[/]   0x12", classes="v")
            yield Static("[dim]u16[/]  0x4812", classes="v")
            yield Static("[dim]u32[/]  0x48121A0F", classes="v")
            yield Static("[dim]f32[/]  1.4842e-04", classes="v")
            yield Static("")
            yield Static("A2L SYMBOL", classes="h")
            yield Static("BLOCK_A.entry_point", classes="accent")
            yield Static("[dim]declared at[/] ecu.a2l:1284", classes="v")
            yield Static("")
            yield Static("MAC", classes="h")
            yield Static("[yellow]●[/] in canonical block", classes="v")
            yield Static("delta vs reference: [yellow]+0x04[/]", classes="v")
