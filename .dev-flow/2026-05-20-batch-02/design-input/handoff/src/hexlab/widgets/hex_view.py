"""Virtualized hex + ASCII view.

Why custom: a `DataTable` could *almost* do this, but a hex view has fixed,
non-tabular formatting (offset │ 16 hex bytes │ ASCII gutter), per-byte
overlays (MAC highlights, diff bg), and needs to scroll millions of rows.
The right shape is a virtualized line-renderer that only generates Rich Text
for the rows currently in the viewport.

This sketch renders a fixed window. The full impl should:
  - Subclass `ScrollView` instead of `Static`, override `render_line(y)`
  - Read bytes lazily from a `bincopy.BinFile` slice
  - Take an `overlays: Iterable[ByteOverlay]` for MAC / diff / selection
"""

from __future__ import annotations

from rich.console import RenderableType
from rich.text import Text
from textual.widget import Widget


def _ascii(b: int) -> str:
    return chr(b) if 0x20 <= b <= 0x7E else "·"


class HexView(Widget):
    """Hex + ASCII pane. Scrolls vertically. 16 bytes per row."""

    DEFAULT_CSS = """
    HexView {
        background: $bg-1;
        color: $fg;
        padding: 1 2;
    }
    """

    can_focus = True

    def __init__(self, rows: list[tuple[int, bytes]], mac_addrs: set[int] | None = None) -> None:
        super().__init__()
        self._rows = rows
        self._mac = mac_addrs or set()

    def render(self) -> RenderableType:
        text = Text(no_wrap=True, overflow="ellipsis")
        # Header
        text.append("  offset    ", style="dim")
        for i in range(16):
            sep = "  " if i == 8 else " "
            text.append(f"{sep}{i:02X}", style="dim")
        text.append("   ", style="dim")
        text.append("ascii", style="dim")
        text.append("\n")

        for addr, chunk in self._rows:
            text.append(f"  {addr:08X}  ", style="bright_black")
            for i, b in enumerate(chunk):
                sep = "  " if i == 8 else " "
                style = ""
                if (addr + i) in self._mac:
                    style = "yellow"
                text.append(f"{sep}{b:02X}", style=style)
            text.append("   ")
            for b in chunk:
                text.append(_ascii(b), style="cyan" if 0x20 <= b <= 0x7E else "bright_black")
            text.append("\n")
        return text
