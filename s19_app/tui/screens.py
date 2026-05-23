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


# --- Calm Dark modal re-skin (batch-02 increment 8, LLR-015.1) --------------
# The three Load / Save / Load-Project modals adopt the Calm Dark token set
# defined in ``styles.tcss`` (`$accent-calm` + the shared dark `$bg-*` /
# `$fg-*` / `$rule` tokens). All modal styling — the dimmed `ModalScreen`
# backdrop, the dialog border / panel surface, the title, the buttons and the
# inputs — lives in ``styles.tcss`` keyed on the `.modal-dialog` /
# `.modal-title` / `.modal-buttons` / `.modal-confirm` classes (and the
# carried-over `#load_dialog` id). No per-screen ``DEFAULT_CSS`` is used: the
# Calm Dark `$bg-*` / `$fg-*` / `$rule` token variables are only in scope for
# the app-level stylesheet (`CSS_PATH = "styles.tcss"`), so the modal rules
# must live there to resolve the tokens. The three modals therefore share one
# accent and one backdrop tone (TC-033 single-accent rule).
#
# This is a VISUAL-ONLY re-skin: no behavior, no path handling, no
# ``validate_project_files`` / ``SaveProjectPayload`` / ``.s19tool/`` workarea
# logic is changed (LLR-015.2 / C-1 / A-5). No hard-coded hex color is used —
# every modal color resolves through a Calm Dark token in ``styles.tcss``.


@dataclass(frozen=True)
class SaveProjectPayload:
    """Parent directory (as entered or browsed) and project folder name for save."""

    parent_folder: str
    project_name: str


class LoadFileScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading S19/HEX/MAC data files or an A2L file.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class so it picks up the
    Calm Dark accent border, panel background and foreground tokens from
    ``styles.tcss``. Behavior is unchanged (LLR-015.2).
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load file (S19/HEX/MAC/A2L):", classes="modal-title"),
            Input(
                placeholder="C:\\path\\to\\file.s19, .hex, .mac, or .a2l",
                id="load_path",
            ),
            Container(
                Button("Load", id="load_ok", classes="modal-confirm"),
                Button("Cancel", id="load_cancel"),
                id="load_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
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
    """Modal dialog for destination folder, optional browse, and project name.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class. Behavior — the
    browse fallback, ``SaveProjectPayload`` construction and the
    ``.s19tool/`` workarea destination — is unchanged (LLR-015.2 / A-5).
    """

    def __init__(self, default_parent: Path) -> None:
        super().__init__()
        self.default_parent = default_parent

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Save project folder under:", classes="modal-title"),
            Input(
                placeholder="C:\\path\\to\\parent\\folder",
                id="project_parent_path",
            ),
            Container(
                Button("Browse...", id="save_browse"),
                id="save_browse_row",
            ),
            Label("Project name (new folder name):", classes="modal-title"),
            Input(placeholder="letters, numbers, - _", id="project_name"),
            Container(
                Button("Save", id="save_ok", classes="modal-confirm"),
                Button("Cancel", id="save_cancel"),
                id="load_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
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
    """Modal dialog for selecting an existing project.

    Re-skinned to the Calm Dark theme in batch-02 increment 8 (LLR-015.1):
    the dialog carries the shared ``.modal-dialog`` class. The project list
    selection behavior is unchanged (LLR-015.2).
    """

    def __init__(self, projects: List[str]):
        super().__init__()
        self.projects = projects

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load project:", classes="modal-title"),
            ListView(
                *[ListItem(Label(name)) for name in self.projects],
                id="project_list",
            ),
            Container(
                Button("Load", id="project_ok", classes="modal-confirm"),
                Button("Cancel", id="project_cancel"),
                id="load_buttons",
                classes="modal-buttons",
            ),
            id="load_dialog",
            classes="modal-dialog",
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
