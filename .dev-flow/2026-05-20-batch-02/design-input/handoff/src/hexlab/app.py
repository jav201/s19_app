"""Hex Lab — Textual app entry point.

Direction B: Rail + Command. The App is a thin shell — it owns global key
bindings, holds the open project, and routes between screens. Each rail item
maps to a Screen. The command bar at the top is a *widget* mounted by every
screen (so addresses / symbols stay one keystroke away no matter where you are).
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from hexlab.screens.workspace import WorkspaceScreen


class HexLabApp(App):
    """Top-level application."""

    CSS_PATH = "styles.tcss"
    TITLE = "hexlab"
    SUB_TITLE = "no project"

    BINDINGS = [
        # Global. Each rail item also has its own number key (1-8) bound on the
        # screen itself, since rail keys don't make sense in modals.
        Binding("ctrl+k", "focus_command", "Command", show=True),
        Binding("ctrl+l", "load_project", "Load", show=True),
        Binding("ctrl+s", "save_project", "Save", show=True),
        Binding("ctrl+d", "cycle_density", "Density", show=False),
        Binding("q", "quit", "Quit", show=True),
    ]

    # ── Density: maps to data-density="dense|normal|comfortable" in the mock ──
    DENSITIES = ("dense", "normal", "comfortable")

    def __init__(self, project_path: Path | None = None) -> None:
        super().__init__()
        self.project_path = project_path
        self._density_idx = 1  # "normal"

    def on_mount(self) -> None:
        # Single screen for the sketch. Full app pushes/pops per rail item.
        self.push_screen(WorkspaceScreen())

    # ─── Actions ──────────────────────────────────────────────────────────

    def action_focus_command(self) -> None:
        """Focus the command bar — Ctrl+K from anywhere."""
        try:
            cmd = self.screen.query_one("#command-input")
        except Exception:
            return
        cmd.focus()

    def action_load_project(self) -> None:
        # Stub. Full app: push LoadProjectModal(); on result, swap project.
        self.notify("Load project — wire to LoadProjectModal", severity="information")

    def action_save_project(self) -> None:
        self.notify("Save project — wire to SaveProjectModal", severity="information")

    def action_cycle_density(self) -> None:
        self._density_idx = (self._density_idx + 1) % len(self.DENSITIES)
        density = self.DENSITIES[self._density_idx]
        # Density is a CSS class on the screen root. styles.tcss has variants.
        self.screen.set_class(density == "dense", "density-dense")
        self.screen.set_class(density == "comfortable", "density-comfortable")
        self.notify(f"Density: {density}")


def main() -> None:
    """Console-script entry."""
    HexLabApp().run()


if __name__ == "__main__":
    main()
