"""Memory-map coverage strip.

Compresses the address space into a single fixed-width row of cells,
each colored by the range it falls in. In the mock this is `mem-map` —
in Textual we render it with Rich `Text` block characters.
"""

from __future__ import annotations

from rich.console import RenderableType
from rich.text import Text
from textual.widget import Widget

from hexlab.core.sample_data import Range


_KIND_STYLE = {
    "boot": "bright_black",
    "code": "cyan",
    "cal":  "yellow",
    "data": "green",
}


class MemoryMap(Widget):
    """Linear memory coverage strip."""

    DEFAULT_CSS = """
    MemoryMap {
        height: 3;
        background: $bg-1;
        border-bottom: solid $rule-soft;
        padding: 1 2;
    }
    """

    def __init__(self, ranges: list[Range], width_cells: int = 80) -> None:
        super().__init__()
        self._ranges = ranges
        self._cells = width_cells

    def render(self) -> RenderableType:
        if not self._ranges:
            return Text("(no ranges)", style="dim")
        lo = min(r.start for r in self._ranges)
        hi = max(r.end for r in self._ranges)
        span = max(hi - lo, 1)
        out = Text(no_wrap=True)
        for c in range(self._cells):
            addr = lo + (c * span) // self._cells
            kind, valid = "data", True
            for r in self._ranges:
                if r.start <= addr < r.end:
                    kind, valid = r.kind, r.valid
                    break
            ch = "█" if valid else "▒"
            out.append(ch, style=_KIND_STYLE.get(kind, "white"))
        return out
