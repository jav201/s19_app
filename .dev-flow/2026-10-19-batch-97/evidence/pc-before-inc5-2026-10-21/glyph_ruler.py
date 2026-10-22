"""Throwaway: a Textual glyph ruler for a real Windows Terminal capture.
Each row: label, then the glyph at a fixed column followed IMMEDIATELY by '|'
and the digits. A glyph WT paints two cells wide covers or pushes the '|'."""
import unicodedata
from rich.text import Text
from textual.app import App
from textual.widgets import Static

GLYPHS = ["a", "◉", "▣", "✓", "⊕", "▼", "⏚", "»", "≡", "▶", "▸", "►", "→", "←",
          "─", "╭", "╮", "╰", "╯", "│", "…", "·", "—", "●", "◈", "✖", "✗", "○",
          "□", "█", "░", "▓", "‥", "◆", "▪", "◇", "⊘", "☑", "⏸"]

class Ruler(App):
    CSS = "Screen { background: #0a0e1b; } Static { color: #e9e9e9; }"
    def compose(self):
        lines = Text()
        for i, g in enumerate(GLYPHS):
            name = unicodedata.name(g, "?")[:26]
            lines.append(f"{i:02d} U+{ord(g):04X} {name:26s} ")
            lines.append(g, style="bold #c9562b")
            lines.append("|0123|", style="#91abec")
            lines.append(g + g + g, style="#56e0d6")
            lines.append("|end\n", style="#91abec")
        yield Static(lines)

if __name__ == "__main__":
    Ruler().run()
