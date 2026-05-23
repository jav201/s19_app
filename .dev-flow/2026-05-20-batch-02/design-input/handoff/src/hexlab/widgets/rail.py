"""Left activity rail — vertical list of screens with badges and an active marker.

Mirrors `b-rail` from `tui-b.css`: 168px wide, left accent bar on the active row,
badges for issue counts. Pure presentational widget — emits `Rail.Selected`
events; the parent screen decides how to route.
"""

from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Static


@dataclass(frozen=True)
class RailEntry:
    key: str           # "ws" | "a2l" | "mac" | …
    icon: str
    label: str
    badge: str | None = None
    badge_kind: str = ""  # "" | "warn" | "err"


DEFAULT_RAIL: tuple[RailEntry, ...] = (
    RailEntry("ws",    "◫", "Workspace"),
    RailEntry("a2l",   "≡", "A2L",       badge="13"),
    RailEntry("mac",   "◉", "MAC",       badge="2",  badge_kind="warn"),
    RailEntry("map",   "▤", "Map"),
    RailEntry("iss",   "!", "Issues",    badge="6",  badge_kind="err"),
    RailEntry("patch", "✎", "Patch",     badge="•",  badge_kind="warn"),
    RailEntry("diff",  "⏚", "Diff"),
    RailEntry("bm",    "✶", "Bookmarks", badge="3"),
)


class RailItem(Static, can_focus=True):
    """One row in the rail."""

    DEFAULT_CSS = """
    RailItem {
        height: 1;
        padding: 0 1;
        color: $fg-muted;
        border-left: vkey $background;
    }
    RailItem:hover { color: $fg; background: $bg-2; }
    RailItem.-active {
        color: $fg;
        background: $bg-2;
        border-left: vkey $accent;
    }
    RailItem.-active > .ic { color: $accent; }
    """

    class Selected(Message):
        def __init__(self, key: str) -> None:
            super().__init__()
            self.key = key

    def __init__(self, entry: RailEntry, active: bool = False) -> None:
        super().__init__(self._render(entry))
        self.entry = entry
        if active:
            self.add_class("-active")

    @staticmethod
    def _render(e: RailEntry) -> str:
        badge = ""
        if e.badge:
            # Badge color is purely decorative here — real impl uses Rich markup
            badge = f"  [dim]{e.badge}[/]"
        return f"[bold]{e.icon}[/]  {e.label}{badge}"

    def on_click(self) -> None:
        self.post_message(self.Selected(self.entry.key))


class Rail(Widget):
    """Vertical activity rail."""

    DEFAULT_CSS = """
    Rail {
        width: 22;
        background: $bg-titlebar;
        border-right: solid $rule;
        padding: 1 0;
    }
    """

    def __init__(self, entries: tuple[RailEntry, ...] = DEFAULT_RAIL,
                 active: str = "ws") -> None:
        super().__init__()
        self._entries = entries
        self._active = active

    def compose(self) -> ComposeResult:
        with Vertical():
            for e in self._entries:
                yield RailItem(e, active=(e.key == self._active))
