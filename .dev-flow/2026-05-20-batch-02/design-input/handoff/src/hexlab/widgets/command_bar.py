"""Top command bar — the ⌘K input + global pills (errors, warnings, coverage, CRC).

This is the same row as `b-cmd` in `tui-b.css`. Mounted by every screen that
uses Direction B's chrome.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Input, Static


class CommandBar(Widget):
    """Persistent command bar across the top of the workspace."""

    DEFAULT_CSS = """
    CommandBar {
        height: 3;
        background: $bg-1;
        border-bottom: solid $rule;
        layout: horizontal;
        padding: 0 1;
    }
    CommandBar > .prompt {
        width: 2;
        color: $accent;
        content-align: center middle;
    }
    CommandBar > Input {
        background: transparent;
        border: none;
        height: 3;
        padding: 0 1;
    }
    CommandBar > .key {
        width: auto;
        padding: 0 1;
        color: $fg-faint;
        border: round $rule;
        margin: 0 1;
    }
    CommandBar > .pill {
        width: auto;
        padding: 0 1;
        color: $fg-muted;
        border: round $rule;
        margin: 0 1;
    }
    CommandBar > .pill.-warn { color: $sev-warn; }
    CommandBar > .pill.-err  { color: $sev-error; }
    """

    def __init__(self, errors: int = 0, warnings: int = 0, coverage: int = 0,
                 crc: str = "—") -> None:
        super().__init__()
        self._errors = errors
        self._warnings = warnings
        self._coverage = coverage
        self._crc = crc

    def compose(self) -> ComposeResult:
        yield Static("›", classes="prompt")
        yield Input(
            placeholder="type a command, address (0x80004000), or symbol (BLOCK_A)…",
            id="command-input",
        )
        yield Static("⌘K", classes="key")
        if self._errors:
            yield Static(f"● {self._errors}", classes="pill -err")
        if self._warnings:
            yield Static(f"● {self._warnings}", classes="pill -warn")
        yield Static(f"{self._coverage}% coverage", classes="pill")
        yield Static(f"CRC {self._crc}", classes="pill")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Parse the command — address, symbol, or `:command`."""
        text = event.value.strip()
        if not text:
            return
        # Sketch only — full impl: address/symbol resolver + command registry
        self.app.notify(f"⌘K → {text}")
        event.input.value = ""
