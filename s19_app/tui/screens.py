from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView

logger = logging.getLogger("s19tui")


@dataclass(frozen=True)
class SaveProjectPayload:
    """Parent directory (as entered or browsed) and project folder name for save."""

    parent_folder: str
    project_name: str


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
            logger.info("LoadFileScreen dismissed by cancel.")
            self.dismiss(None)
            return
        if event.button.id == "load_ok":
            value = self.query_one("#load_path", Input).value.strip()
            logger.info("LoadFileScreen load_ok pressed. has_value=%s", bool(value))
            if not value:
                return
            logger.info("LoadFileScreen dismissing with path=%s", value)
            self.dismiss(Path(value))


class SaveProjectScreen(ModalScreen[Optional[SaveProjectPayload]]):
    """Modal dialog for destination folder, optional browse, and project name."""

    def __init__(self, default_parent: Path) -> None:
        super().__init__()
        self.default_parent = default_parent

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Save project folder under:"),
            Input(
                placeholder="C:\\path\\to\\parent\\folder",
                id="project_parent_path",
            ),
            Container(
                Button("Browse...", id="save_browse"),
                id="save_browse_row",
            ),
            Label("Project name (new folder name):"),
            Input(placeholder="letters, numbers, - _", id="project_name"),
            Container(
                Button("Save", id="save_ok"),
                Button("Cancel", id="save_cancel"),
                id="load_buttons",
            ),
            id="load_dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#project_parent_path", Input).value = str(self.default_parent)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_cancel":
            self.dismiss(None)
            return
        if event.button.id == "save_browse":
            try:
                import tkinter as tk
                from tkinter import filedialog
            except Exception as exc:
                logger.warning("Folder browse unavailable: %s", exc)
                return
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            picked = filedialog.askdirectory()
            root.destroy()
            if picked:
                self.query_one("#project_parent_path", Input).value = picked
            return
        if event.button.id == "save_ok":
            parent = self.query_one("#project_parent_path", Input).value.strip()
            name = self.query_one("#project_name", Input).value.strip()
            if not parent or not name:
                return
            self.dismiss(SaveProjectPayload(parent_folder=parent, project_name=name))


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
