from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView


class LoadFileScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading S19/HEX/MAC data files or an A2L file."""

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load file (S19/HEX/MAC/A2L):"),
            Input(
                placeholder="C:\\path\\to\\file.s19, .hex, .mac, or .a2l",
                id="load_path",
            ),
            Container(
                Button("Load", id="load_ok"),
                Button("Cancel", id="load_cancel"),
                id="load_buttons",
            ),
            id="load_dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load_cancel":
            self.dismiss(None)
            return
        if event.button.id == "load_ok":
            value = self.query_one("#load_path", Input).value.strip()
            if not value:
                return
            self.dismiss(Path(value))


class SaveProjectScreen(ModalScreen[Optional[str]]):
    """Modal dialog for saving a project name."""

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Save project as:"),
            Input(placeholder="Project name (letters, numbers, - _)", id="project_name"),
            Container(
                Button("Save", id="save_ok"),
                Button("Cancel", id="save_cancel"),
                id="load_buttons",
            ),
            id="load_dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_cancel":
            self.dismiss(None)
            return
        if event.button.id == "save_ok":
            value = self.query_one("#project_name", Input).value.strip()
            if not value:
                return
            self.dismiss(value)


class LoadProjectScreen(ModalScreen[Optional[str]]):
    """Modal dialog for selecting an existing project."""

    def __init__(self, projects: List[str]):
        super().__init__()
        self.projects = projects

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load project:"),
            ListView(
                *[ListItem(Label(name)) for name in self.projects],
                id="project_list",
            ),
            Container(
                Button("Load", id="project_ok"),
                Button("Cancel", id="project_cancel"),
                id="load_buttons",
            ),
            id="load_dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "project_cancel":
            self.dismiss(None)
            return
        if event.button.id == "project_ok":
            selected = self.query_one("#project_list", ListView).highlighted_child
            if selected is None:
                return
            label_widget = selected.query_one(Label)
            name = label_widget.text if hasattr(label_widget, "text") else str(label_widget)
            self.dismiss(name)
