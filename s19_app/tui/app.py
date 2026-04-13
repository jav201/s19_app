from __future__ import annotations

from collections import deque
import json
from pathlib import Path
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, ScrollableContainer
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    Static,
)

from ..core import S19File
from ..hexfile import IntelHexFile
from .a2l import parse_a2l_file, render_a2l_view, validate_a2l_tags
from .hexview import (
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
    find_string_in_mem,
    render_hex_view_text,
)
from .mac import parse_mac_file
from .models import LoadedFile
from .screens import LoadFileScreen, LoadProjectScreen, SaveProjectScreen
from .workspace import (
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    S19_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_TEMP,
    copy_into_workarea,
    ensure_workarea,
    resolve_input_path,
    sanitize_project_name,
    setup_logging,
    validate_project_files,
)


def _a2l_tag_in_memory_display(tag: dict) -> str:
    if not tag.get("memory_checked"):
        return "n/a"
    if tag.get("in_memory") is True:
        return "yes"
    return "no"


def _a2l_tag_row_invalid(tag: dict) -> bool:
    if not tag.get("schema_ok", True):
        return True
    return bool(tag.get("memory_checked") and tag.get("in_memory") is False)


def _build_a2l_name_index(a2l_data: Optional[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    if not a2l_data:
        return index
    for tag in a2l_data.get("tags", []):
        name = str(tag.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        index.setdefault(key, []).append(tag)
    return index


class S19TuiApp(App):
    """Main TUI app with workarea, project management, and views."""

    TITLE = "Hex Edit Tool"
    CSS = """
    Screen {
        layout: vertical;
        padding: 1;
    }

    #view_bar {
        layout: horizontal;
        height: auto;
        padding-bottom: 1;
    }

    #view_bar Button {
        margin-right: 1;
    }

    .hidden {
        display: none;
    }

    #main_layout {
        layout: grid;
        grid-size: 3 2;
        grid-columns: 1fr 1fr 2fr;
        grid-rows: 1fr 1fr;
        grid-gutter: 1;
        height: 100%;
    }

    #alt_layout {
        layout: grid;
        grid-size: 2 2;
        grid-columns: 2fr 1fr;
        grid-rows: 1fr 1fr;
        grid-gutter: 1;
        height: 100%;
    }

    #mac_layout {
        layout: grid;
        grid-size: 2 2;
        grid-columns: 2fr 1fr;
        grid-rows: 1fr 1fr;
        grid-gutter: 1;
        height: 100%;
    }

    #files_panel {
        border: round $primary;
        padding: 1;
    }

    #sections_panel {
        border: round $primary;
        padding: 1;
    }

    #hex_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #a2l_panel {
        border: round $primary;
        padding: 1;
    }

    #status_panel {
        border: round $primary;
        padding: 1;
    }

    .alt_panel {
        border: round $primary;
        padding: 1;
    }

    #alt_hex_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #alt_tags_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #mac_hex_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #mac_content_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #alt_actions_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
    }

    #a2l_tags_filters {
        layout: horizontal;
        height: auto;
        padding-bottom: 1;
    }

    #a2l_tags_filter_input {
        width: 1fr;
    }

    #a2l_filter_menu {
        border: round $primary;
        padding: 1;
        height: 8;
    }

    #a2l_filter_menu.hidden {
        display: none;
    }

    #progress_bar {
        margin-top: 1;
    }

    #a2l_view {
        height: 100%;
        overflow: auto;
    }

    #hex_scroll {
        height: 100%;
        overflow: auto;
    }

    #hex_controls {
        layout: horizontal;
        height: auto;
        padding-bottom: 1;
    }

    #search_input, #goto_input {
        width: 1fr;
    }

    #alt_hex_controls,
    #mac_hex_controls {
        layout: horizontal;
        height: auto;
        padding-bottom: 1;
    }

    #alt_search_input, #alt_goto_input,
    #mac_search_input, #mac_goto_input {
        width: 1fr;
    }

    #a2l_scroll {
        height: 100%;
        overflow: auto;
    }

    #mac_scroll {
        height: 100%;
        overflow: auto;
    }

    #a2l_tags_list {
        height: 100%;
    }

    #alt_hex_scroll {
        height: 100%;
        overflow: auto;
    }


    .valid {
        color: green;
    }

    .invalid {
        color: red;
    }

    #load_dialog {
        border: round $accent;
        padding: 1;
        width: 70%;
    }

    #load_buttons {
        layout: horizontal;
        height: auto;
        padding-top: 1;
        dock: bottom;
    }

    #files_title, #sections_title, #hex_title, #status_title, #a2l_title, #a2l_tags_title, #alt_hex_title, #alt_actions_title {
        text-align: center;
        width: 100%;
        background: $primary;
        color: $text;
        padding: 0 1;
        margin-bottom: 1;
        text-style: bold;
    }
    """

    BINDINGS = [
        ("l", "load_file", "Load file"),
        ("r", "refresh_files", "Refresh workarea"),
        ("o", "open_workarea", "Open workarea"),
        ("s", "save_project", "Save project"),
        ("p", "load_project", "Load project"),
        ("j", "dump_a2l_json", "Dump A2L JSON"),
        ("1", "view_main", "Main view"),
        ("2", "view_alt", "Alt view"),
        ("3", "view_mac", "MAC view"),
        ("q", "quit", "Quit"),
    ]

    workarea: Path
    current_file: reactive[Optional[LoadedFile]] = reactive(None)
    current_project: Optional[str] = None
    current_a2l_path: Optional[Path] = None
    current_a2l_data: Optional[dict] = None
    last_search_text: Optional[str] = None
    last_search_address: Optional[int] = None
    log_lines: deque[str]
    a2l_tags_filter_mode: str = "all"
    a2l_tags_filter_text: str = ""
    a2l_tags_filter_field: str = "name"
    a2l_tags_filter_fields = [
        "all",
        "name",
        "address",
        "length",
        "source",
        "in_memory",
        "limits",
        "unit",
        "bits",
        "endian",
        "virtual",
        "function_group",
        "access",
        "datatype",
        "description",
        "memory_region",
    ]

    def __init__(self, base_dir: Optional[Path] = None, load_path: Optional[Path] = None):
        super().__init__()
        self.base_dir = base_dir or Path.cwd()
        self.logger = setup_logging(self.base_dir)
        self.workarea = ensure_workarea(self.base_dir)
        self.load_path = load_path
        self.log_lines = deque(maxlen=4)
        self.logger.info("App initialized. base_dir=%s workarea=%s", self.base_dir, self.workarea)

    def compose(self) -> ComposeResult:
        """Lay out the grid tiles and widgets."""
        yield Header()
        yield Container(
            Button("Main View", id="view_hex_button"),
            Button("A2L View", id="view_a2l_button"),
            Button("MAC View", id="view_mac_button"),
            id="view_bar",
        )
        yield Container(
            Container(
                Label("Workarea Files", id="files_title"),
                ListView(id="files_list"),
                id="files_panel",
            ),
            Container(
                Label("Data Sections", id="sections_title"),
                ListView(id="sections_list"),
                id="sections_panel",
            ),
            Container(
                Label("Hex Viewer", id="hex_title"),
                Container(
                    Input(placeholder="Search ASCII text", id="search_input"),
                    Button("Find Next", id="search_button"),
                    Input(placeholder="Goto 0xADDR", id="goto_input"),
                    Button("Goto", id="goto_button"),
                    id="hex_controls",
                ),
                ScrollableContainer(
                    Static("", id="hex_view", markup=False),
                    id="hex_scroll",
                ),
                id="hex_panel",
            ),
            Container(
                Label("A2L View", id="a2l_title"),
                ScrollableContainer(
                    Static("", id="a2l_view", markup=False),
                    id="a2l_scroll",
                ),
                id="a2l_panel",
            ),
            Container(
                Label("Status", id="status_title"),
                Label("Ready.", id="status_text"),
                Label("Project: (none)", id="project_text"),
                Label("A2L: (none)", id="a2l_text"),
                ProgressBar(total=100, id="progress_bar"),
                Label("", id="log_line_1"),
                Label("", id="log_line_2"),
                Label("", id="log_line_3"),
                Label("", id="log_line_4"),
                id="status_panel",
            ),
            id="main_layout",
        )
        yield Container(
            Container(
                Label("A2L Tags", id="a2l_tags_title"),
                Container(
                    Input(placeholder="Filter tags", id="a2l_tags_filter_input"),
                    Button("Field: name", id="a2l_filter_field"),
                    Button("All", id="a2l_filter_all"),
                    Button("Invalid", id="a2l_filter_invalid"),
                    Button("In-Memory", id="a2l_filter_inmem"),
                    id="a2l_tags_filters",
                ),
                Container(
                    ListView(id="a2l_filter_menu_list"),
                    id="a2l_filter_menu",
                    classes="hidden",
                ),
                ListView(id="a2l_tags_list"),
                id="alt_tags_panel",
            ),
            Container(
                Label("Hex Viewer", id="alt_hex_title"),
                Container(
                    Input(placeholder="Search ASCII text", id="alt_search_input"),
                    Button("Find Next", id="alt_search_button"),
                    Input(placeholder="Goto 0xADDR", id="alt_goto_input"),
                    Button("Goto", id="alt_goto_button"),
                    id="alt_hex_controls",
                ),
                ScrollableContainer(
                    Static("", id="alt_hex_view", markup=False),
                    id="alt_hex_scroll",
                ),
                id="alt_hex_panel",
            ),
            id="alt_layout",
            classes="hidden",
        )
        yield Container(
            Container(
                Label("MAC File Content", id="mac_title"),
                ScrollableContainer(
                    ListView(id="mac_records_list"),
                    id="mac_scroll",
                ),
                id="mac_content_panel",
            ),
            Container(
                Label("Hex Viewer", id="mac_hex_title"),
                Container(
                    Input(placeholder="Search ASCII text", id="mac_search_input"),
                    Button("Find Next", id="mac_search_button"),
                    Input(placeholder="Goto 0xADDR", id="mac_goto_input"),
                    Button("Goto", id="mac_goto_button"),
                    id="mac_hex_controls",
                ),
                ScrollableContainer(
                    Static("", id="mac_hex_view", markup=False),
                    id="mac_hex_scroll",
                ),
                id="mac_hex_panel",
            ),
            id="mac_layout",
            classes="hidden",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_files()
        self._update_a2l_filter_menu()
        if self.load_path:
            self.logger.info("Startup load requested: %s", self.load_path)
            self._load_path_from_user_input(self.load_path)

    def refresh_files(self) -> None:
        """Refresh file list from the workarea temp folder."""
        list_view = self.query_one("#files_list", ListView)
        list_view.clear()
        files = sorted(self.workarea.glob("*"))
        for item in files:
            if item.is_file():
                list_view.append(ListItem(Label(item.name)))
        self.logger.info("Workarea refreshed. files=%d", len([f for f in files if f.is_file()]))

    def action_refresh_files(self) -> None:
        self.refresh_files()

    def action_load_file(self) -> None:
        """Open path dialog for S19/HEX/MAC/A2L."""
        self.logger.info("Load file action triggered.")
        self.push_screen(LoadFileScreen(), self._handle_load_dialog)

    def action_open_workarea(self) -> None:
        """Open the workarea directory in Explorer."""
        try:
            import subprocess

            subprocess.Popen(["explorer", str(self.workarea)])
            self.set_status(f"Opened workarea: {self.workarea}")
            self.logger.info("Opened workarea in explorer: %s", self.workarea)
        except Exception as exc:
            self.set_status(f"Failed to open workarea: {exc}")
            self.logger.exception("Failed to open workarea.")

    def action_save_project(self) -> None:
        """Prompt to save current selection as a project."""
        if not self.current_file and not self.current_a2l_path:
            self.logger.info("Save project action triggered with no loaded files.")
        elif self.current_file:
            self.logger.info("Save project action triggered for %s", self.current_file.path)
        else:
            self.logger.info("Save project action triggered with A2L only.")
        self.push_screen(SaveProjectScreen(), self._handle_save_dialog)

    def action_load_project(self) -> None:
        """Prompt to load an existing project."""
        projects = self.list_projects()
        if not projects:
            self.set_status("No saved projects found.")
            self.logger.info("No projects found in workarea.")
            return
        self.logger.info("Load project action triggered. projects=%s", projects)
        self.push_screen(LoadProjectScreen(projects), self._handle_load_project)

    def action_dump_a2l_json(self) -> None:
        """Dump parsed A2L data into JSON in temp."""
        if not self.current_a2l_data:
            self.set_status("No A2L data to export.")
            self.logger.warning("A2L export requested with no data.")
            return
        temp_dir = self.workarea / WORKAREA_TEMP
        temp_dir.mkdir(parents=True, exist_ok=True)
        base_name = (
            self.current_a2l_path.stem
            if self.current_a2l_path
            else (self.current_file.path.stem if self.current_file else "a2l")
        )
        output = temp_dir / f"{base_name}.a2l.json"
        output.write_text(json.dumps(self.current_a2l_data, indent=2), encoding="utf-8")
        self.set_status(f"A2L JSON saved: {output.name}")
        self.logger.info("A2L JSON exported: %s", output)

    def action_view_main(self) -> None:
        """Switch to the main view."""
        main_layout = self.query_one("#main_layout")
        alt_layout = self.query_one("#alt_layout")
        mac_layout = self.query_one("#mac_layout")
        main_layout.remove_class("hidden")
        alt_layout.add_class("hidden")
        mac_layout.add_class("hidden")

    def action_view_alt(self) -> None:
        """Switch to the alternate view."""
        main_layout = self.query_one("#main_layout")
        alt_layout = self.query_one("#alt_layout")
        mac_layout = self.query_one("#mac_layout")
        main_layout.add_class("hidden")
        alt_layout.remove_class("hidden")
        mac_layout.add_class("hidden")

    def action_view_mac(self) -> None:
        """Switch to the MAC view."""
        main_layout = self.query_one("#main_layout")
        alt_layout = self.query_one("#alt_layout")
        mac_layout = self.query_one("#mac_layout")
        main_layout.add_class("hidden")
        alt_layout.add_class("hidden")
        mac_layout.remove_class("hidden")

    def _handle_save_dialog(self, name: Optional[str]) -> None:
        if name is None:
            self.logger.info("Save project canceled.")
            return
        cleaned = sanitize_project_name(name)
        if not cleaned:
            self.set_status("Invalid project name.")
            self.logger.warning("Invalid project name: %s", name)
            return
        project_dir = self.workarea / cleaned
        project_dir.mkdir(parents=True, exist_ok=True)
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.set_status(error)
            self.logger.warning("Project validation failed: %s", error)
            return
        if data_files and self.current_file and self.current_file.path.suffix.lower() in PROJECT_DATA_EXTENSIONS:
            self.set_status("Project already has a data file.")
            self.logger.warning("Project already has data file: %s", project_dir)
            return
        if a2l_files and self.current_a2l_path and self.current_a2l_path.suffix.lower() in A2L_EXTENSIONS:
            self.set_status("Project already has an A2L file.")
            self.logger.warning("Project already has A2L file: %s", project_dir)
            return
        if self.current_file:
            saved = copy_into_workarea(self.current_file.path, project_dir)
            self.logger.info("Project saved. name=%s file=%s", cleaned, saved)
        if self.current_a2l_path:
            saved_a2l = copy_into_workarea(self.current_a2l_path, project_dir)
            self.logger.info("Project saved A2L. name=%s file=%s", cleaned, saved_a2l)
        self.current_project = cleaned
        if self.current_file:
            self.set_status(f"Saved project '{cleaned}' -> {self.current_file.path.name}")
        else:
            self.set_status(f"Saved project '{cleaned}'")
        self.update_project_labels()
        self.refresh_files()

    def _handle_load_project(self, name: Optional[str]) -> None:
        if name is None:
            self.logger.info("Load project canceled.")
            return
        project_dir = self.workarea / name
        if not project_dir.exists():
            self.set_status(f"Project not found: {name}")
            self.logger.warning("Project not found: %s", name)
            return
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.set_status(error)
            self.logger.warning("Project validation failed: %s", error)
            return
        if not data_files:
            self.set_status(f"No supported files in project: {name}")
            self.logger.warning("No data files in project: %s", name)
            return
        self.current_project = name
        self.load_selected_file(data_files[0], a2l_files)
        self.set_status(f"Loaded project '{name}' -> {data_files[0].name}")
        self.logger.info("Project loaded. name=%s file=%s", name, data_files[0])
        self.update_project_labels()

    def list_projects(self) -> List[str]:
        projects = []
        for item in sorted(self.workarea.iterdir()):
            if item.is_dir() and item.name != WORKAREA_TEMP:
                projects.append(item.name)
        return projects

    def _sync_loaded_file_to_project(self, project_name: str) -> None:
        """Copy loaded data file into active project if allowed."""
        if not self.current_file:
            return
        project_dir = self.workarea / project_name
        project_dir.mkdir(parents=True, exist_ok=True)
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.logger.warning("Project validation failed during sync: %s", error)
            return
        if data_files:
            self.logger.info("Project already has data file, skipping sync: %s", project_dir)
            return
        copy_into_workarea(self.current_file.path, project_dir)
        self.logger.info("Synced data file into project: %s", project_dir)

    def _sync_loaded_a2l_to_project(self, project_name: str) -> None:
        """Copy loaded A2L file into active project if allowed."""
        if not self.current_a2l_path:
            return
        project_dir = self.workarea / project_name
        project_dir.mkdir(parents=True, exist_ok=True)
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.logger.warning("Project validation failed during A2L sync: %s", error)
            return
        if a2l_files:
            self.logger.info("Project already has A2L file, skipping sync: %s", project_dir)
            return
        copy_into_workarea(self.current_a2l_path, project_dir)
        self.logger.info("Synced A2L file into project: %s", project_dir)

    def _load_path_from_user_input(self, path: Path) -> None:
        """Resolve path and dispatch to data load (S19/HEX/MAC) or A2L load."""
        normalized = resolve_input_path(path, self.base_dir)
        if not normalized:
            self.set_status(f"File not found: {path}")
            self.logger.warning("File not found: %s", path)
            return
        suffix = normalized.suffix.lower()
        if suffix in A2L_EXTENSIONS:
            self.load_a2l_from_path(path)
        elif suffix in SUPPORTED_EXTENSIONS:
            self.load_from_path(path)
        else:
            self.set_status(f"Unsupported file type: {normalized.suffix}")
            self.logger.warning("Unsupported file type: %s", normalized.suffix)

    def _handle_load_dialog(self, path: Optional[Path]) -> None:
        if path is None:
            return
        self._load_path_from_user_input(path)

    def load_from_path(self, path: Path) -> None:
        """Load supported data file into temp and render views."""
        normalized = resolve_input_path(path, self.base_dir)
        if not normalized:
            self.set_status(f"File not found: {path}")
            self.logger.warning("File not found: %s", path)
            return
        if normalized.suffix.lower() not in SUPPORTED_EXTENSIONS:
            self.set_status(f"Unsupported file type: {normalized.suffix}")
            self.logger.warning("Unsupported file type: %s", normalized.suffix)
            return
        temp_dir = self.workarea / WORKAREA_TEMP
        self.set_progress(10, "Copying into workarea temp...")
        copied = copy_into_workarea(normalized, temp_dir)
        self.refresh_files()
        self.set_progress(50, f"Loading {copied.name}...")
        self.logger.info("File copied to temp: %s", copied)
        self.load_selected_file(copied)
        self.set_progress(100, f"Loaded {copied.name}")

        if self.current_project:
            self._sync_loaded_file_to_project(self.current_project)

    def load_a2l_from_path(self, path: Path) -> None:
        """Load A2L file into temp, parse it, and update view."""
        normalized = resolve_input_path(path, self.base_dir)
        if not normalized:
            self.set_status(f"A2L file not found: {path}")
            self.logger.warning("A2L file not found: %s", path)
            return
        if normalized.suffix.lower() not in A2L_EXTENSIONS:
            self.set_status(f"Unsupported A2L type: {normalized.suffix}")
            self.logger.warning("Unsupported A2L type: %s", normalized.suffix)
            return
        if self.current_project:
            project_dir = self.workarea / self.current_project
            _, a2l_files, error = validate_project_files(project_dir)
            if error:
                self.set_status(error)
                self.logger.warning("Project validation failed: %s", error)
                return
            if a2l_files:
                self.set_status("Project already has an A2L file.")
                self.logger.warning("Project already has A2L file: %s", project_dir)
                return
        temp_dir = self.workarea / WORKAREA_TEMP
        self.set_progress(10, "Copying A2L into workarea temp...")
        copied = copy_into_workarea(normalized, temp_dir)
        self.refresh_files()
        self.set_progress(50, f"Parsing {copied.name}...")
        self.current_a2l_path = copied
        self.current_a2l_data = parse_a2l_file(copied)
        if self.current_file:
            self.current_file.a2l_path = copied
            self.current_file.a2l_data = self.current_a2l_data
        self.update_a2l_view()
        self.update_project_labels()
        self.set_progress(100, f"Loaded {copied.name}")
        self.set_status(f"A2L loaded: {copied.name}")
        self.logger.info("A2L loaded: %s", copied)

        if self.current_project:
            self._sync_loaded_a2l_to_project(self.current_project)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "files_list":
            if event.item is None:
                return
            self._load_from_item(event.item)
            return
        if event.list_view.id == "sections_list":
            if event.item is None:
                return
            self._jump_to_section(event.item)
            return
        if event.list_view.id == "a2l_tags_list":
            if event.item is None:
                return
            self._jump_to_tag(event.item)
            return
        if event.list_view.id == "a2l_filter_menu_list":
            if event.item is None:
                return
            field = getattr(event.item, "data", None)
            if field:
                self._set_a2l_filter_field(field)
            return
        if event.list_view.id == "mac_records_list":
            if event.item is None:
                return
            self._jump_to_mac_record(event.item)
            return

    def _load_from_item(self, item: ListItem) -> None:
        label_widget = item.query_one(Label)
        if hasattr(label_widget, "text"):
            filename = label_widget.text
        else:
            filename = str(label_widget)
        candidate = self.workarea / filename
        if candidate.exists():
            self.logger.info("Loading from workarea selection: %s", candidate)
            if candidate.suffix.lower() in A2L_EXTENSIONS:
                self.load_a2l_from_path(candidate)
            else:
                self.load_selected_file(candidate)

    def _jump_to_section(self, item: ListItem) -> None:
        section_range = getattr(item, "data", None)
        if section_range:
            start, _ = section_range
            self.update_hex_view(start)

    def _jump_to_tag(self, item: ListItem) -> None:
        tag_info = getattr(item, "data", None)
        if not tag_info:
            return
        addr = tag_info.get("address")
        if isinstance(addr, int):
            self.update_alt_hex_view(addr)
            self.set_status(f"Tag at 0x{addr:08X}")

    def _jump_to_mac_record(self, item: ListItem) -> None:
        """
        Summary:
            Focus the MAC hex panel on the address carried by a selected MAC table row.

        Args:
            item (ListItem): Row from ``#mac_records_list``; ``item.data`` may include
                ``address`` (int) when the row parsed successfully.

        Returns:
            None

        Data Flow:
            - Read optional ``address`` from list item payload.
            - Call ``update_mac_hex_view`` when address is an integer.
            - Update status line with formatted address.

        Dependencies:
            Uses:
                - ``update_mac_hex_view``
                - ``set_status``
            Used by:
                - ``on_list_view_selected`` for ``mac_records_list``
        """
        info = getattr(item, "data", None)
        if not info:
            return
        addr = info.get("address")
        if isinstance(addr, int):
            self.update_mac_hex_view(addr)
            self.set_status(f"MAC tag at 0x{addr:08X}")

    def _load_mac_file(self, path: Path, a2l_files: Optional[list[Path]] = None) -> LoadedFile:
        """
        Summary:
            Parse a ``.mac`` address map, attach optional A2L metadata, and build a
            ``LoadedFile`` suitable for the MAC viewer and hex panel.

        Args:
            path (Path): Path to the ``.mac`` file (UTF-8 text).
            a2l_files (Optional[list[Path]]): If provided, first entry is parsed as A2L;
                otherwise ``current_a2l_path`` / ``current_a2l_data`` are used when set.

        Returns:
            LoadedFile: ``file_type`` ``mac``, sparse ``mem_map`` at parsed addresses,
            ``mac_records`` / ``mac_diagnostics`` from the parser, and merged A2L fields.

        Data Flow:
            - Run ``parse_mac_file`` to obtain records and diagnostics.
            - Build ``mem_map`` as a single-byte placeholder per successfully parsed address.
            - Derive ``row_bases`` via ``build_row_bases``; empty ``ranges`` for MAC-only load.
            - Resolve A2L path/data from project load arguments or current session state.

        Dependencies:
            Uses:
                - ``parse_mac_file``
                - ``parse_a2l_file``
                - ``build_row_bases``
            Used by:
                - ``load_selected_file`` MAC extension branch
        """
        mac_data = parse_mac_file(path)
        records = mac_data.get("records", [])
        diagnostics = [str(item) for item in mac_data.get("diagnostics", [])]
        valid_addresses = sorted(
            {
                int(item["address"])
                for item in records
                if item.get("parse_ok") and isinstance(item.get("address"), int)
            }
        )
        mem_map = {addr: 0 for addr in valid_addresses}
        row_bases = build_row_bases(mem_map)
        ranges: list[tuple[int, int]] = []
        range_validity: list[bool] = []
        errors = [{"line": None, "message": entry} for entry in diagnostics]
        a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
        a2l_data = parse_a2l_file(a2l_path) if a2l_path else self.current_a2l_data
        return LoadedFile(
            path=path,
            file_type="mac",
            mem_map=mem_map,
            row_bases=row_bases,
            ranges=ranges,
            range_validity=range_validity,
            errors=errors,
            a2l_path=a2l_path,
            a2l_data=a2l_data,
            mac_records=records,
            mac_diagnostics=diagnostics,
        )

    def load_selected_file(self, path: Path, a2l_files: Optional[list[Path]] = None) -> None:
        """
        Summary:
            Load S19, Intel HEX, or MAC data from disk and refresh all TUI panels that depend
            on ``current_file`` and optional A2L state.

        Args:
            path (Path): File to parse (extension selects loader branch).
            a2l_files (Optional[list[Path]]): Optional A2L paths when loading from a project
                directory (first file used).

        Returns:
            None

        Data Flow:
            - Dispatch on suffix to S19, HEX, or MAC construction of ``LoadedFile``.
            - Assign ``current_file`` and sync global A2L fields when payload includes them.
            - Refresh sections, hex views, MAC table, A2L views, and status labels.

        Dependencies:
            Uses:
                - ``S19File`` / ``IntelHexFile`` / ``_load_mac_file``
                - ``build_mem_map_s19``, ``build_row_bases``, range validity builders
                - ``parse_a2l_file``
            Used by:
                - ``load_from_path``, project load handler, workarea file list selection
        """
        suffix = path.suffix.lower()
        try:
            self.logger.info("Loading file: %s", path)
            if suffix in S19_EXTENSIONS:
                s19 = S19File(str(path))
                mem_map = build_mem_map_s19(s19)
                row_bases = build_row_bases(mem_map)
                ranges = s19._get_memory_ranges()
                range_validity = build_range_validity_s19(s19, ranges)
                errors = s19.get_errors()
                a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
                a2l_data = parse_a2l_file(a2l_path) if a2l_path else self.current_a2l_data
                loaded = LoadedFile(
                    path=path,
                    file_type="s19",
                    mem_map=mem_map,
                    row_bases=row_bases,
                    ranges=ranges,
                    range_validity=range_validity,
                    errors=errors,
                    a2l_path=a2l_path,
                    a2l_data=a2l_data,
                )
            elif suffix in HEX_EXTENSIONS:
                hex_file = IntelHexFile(str(path))
                mem_map = dict(hex_file.memory)
                row_bases = build_row_bases(mem_map)
                ranges = hex_file.get_ranges()
                range_validity = build_range_validity_hex(hex_file, ranges)
                errors = hex_file.get_errors()
                a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
                a2l_data = parse_a2l_file(a2l_path) if a2l_path else self.current_a2l_data
                loaded = LoadedFile(
                    path=path,
                    file_type="hex",
                    mem_map=mem_map,
                    row_bases=row_bases,
                    ranges=ranges,
                    range_validity=range_validity,
                    errors=errors,
                    a2l_path=a2l_path,
                    a2l_data=a2l_data,
                )
            elif suffix in MAC_EXTENSIONS:
                loaded = self._load_mac_file(path, a2l_files)
            else:
                self.set_status(f"Unsupported file type: {suffix}")
                self.logger.warning("Unsupported file type in loader: %s", suffix)
                return
        except Exception as exc:
            self.set_status(f"Load failed: {exc}")
            self.logger.exception("Load failed for %s", path)
            return
        self.current_file = loaded
        if loaded.a2l_data:
            self.current_a2l_path = loaded.a2l_path
            self.current_a2l_data = loaded.a2l_data
        self.update_sections()
        self.update_hex_view()
        self.update_alt_hex_view()
        self.update_mac_hex_view()
        self.update_mac_view()
        self.update_a2l_view()
        self.update_project_labels()
        self.set_file_status(f"Loaded {path.name}")
        self._append_log_line(f"Loaded {path.name}")
        self.logger.info("Loaded file successfully: %s", path)

    def update_sections(self) -> None:
        """Update the ranges list with validity coloring."""
        sections = self.query_one("#sections_list", ListView)
        sections.clear()
        if not self.current_file:
            return
        for (start, end), is_valid in zip(
            self.current_file.ranges, self.current_file.range_validity
        ):
            size = end - start
            label = Label(f"0x{start:08X} - 0x{end - 1:08X} ({size} bytes)")
            label.add_class("valid" if is_valid else "invalid")
            item = ListItem(label)
            item.data = (start, end)
            sections.append(item)
        self.logger.info("Sections updated. count=%d", len(self.current_file.ranges))

    def update_hex_view(self, focus_address: Optional[int] = None) -> None:
        """Render hex view around a focus address if provided."""
        hex_view = self.query_one("#hex_view", Static)
        if not self.current_file:
            hex_view.update("No file loaded.")
            return
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
            )
        )
        if focus_address is not None:
            self.logger.info("Hex view focused at 0x%08X", focus_address)

    def update_alt_hex_view(self, focus_address: Optional[int] = None) -> None:
        """Render alt hex view around a focus address if provided."""
        alt_hex_view = self.query_one("#alt_hex_view", Static)
        if not self.current_file:
            alt_hex_view.update("No file loaded.")
            return
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        alt_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
            )
        )

    def update_mac_hex_view(self, focus_address: Optional[int] = None) -> None:
        """Render MAC hex view around a focus address if provided."""
        mac_hex_view = self.query_one("#mac_hex_view", Static)
        if not self.current_file:
            mac_hex_view.update("No file loaded.")
            return
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
            )
        )

    def update_mac_view(self) -> None:
        """
        Summary:
            Populate the MAC viewer list with parsed ``.mac`` rows, A2L cross-check columns,
            combined status coloring, and aggregate counts.

        Args:
            (none; reads ``current_file``, ``current_a2l_data``, and widget ``#mac_records_list``.)

        Returns:
            None

        Data Flow:
            - Clear and repopulate ``#mac_records_list`` with header, fixed-width rows, summary.
            - Build case-insensitive A2L name index from loaded tags.
            - For each MAC record, compute parse validity, A2L membership, optional image check,
              row status string, and CSS class (``valid`` / ``invalid``).

        Dependencies:
            Uses:
                - ``_build_a2l_name_index``
                - ``query_one`` / ``ListView`` / ``Label`` / ``ListItem``
            Used by:
                - ``load_selected_file`` post-load refresh
                - ``update_a2l_view`` when A2L data changes
        """
        mac_list = self.query_one("#mac_records_list", ListView)
        mac_list.clear()
        if not self.current_file or self.current_file.file_type != "mac":
            mac_list.append(ListItem(Label("No MAC loaded.")))
            return
        records = self.current_file.mac_records or []
        if not records:
            mac_list.append(ListItem(Label("No MAC records parsed.")))
            return

        a2l_name_index = _build_a2l_name_index(self.current_a2l_data)
        rows: list[tuple] = []
        row_meta: list[dict] = []
        total_valid = 0
        total_invalid = 0
        total_in_a2l = 0
        total_out_of_mem = 0
        total_parse_errors = 0

        for record in records:
            line_no = int(record.get("line_number") or 0)
            name = str(record.get("name") or "").strip()
            address = record.get("address")
            parse_ok = bool(record.get("parse_ok"))
            parse_error = str(record.get("parse_error") or "")
            if not parse_ok:
                total_parse_errors += 1

            in_a2l = False
            a2l_match_text = ""
            if name:
                matches = a2l_name_index.get(name.lower(), [])
                if matches:
                    in_a2l = True
                    total_in_a2l += 1
                    best = matches[0]
                    a2l_match_text = f"{best.get('section', '?')}:{best.get('name', name)}"

            memory_checked = False
            in_memory = None
            if self.current_file.file_type in {"s19", "hex"} and isinstance(address, int):
                memory_checked = True
                in_memory = address in self.current_file.mem_map

            in_mem_text = "n/a"
            if memory_checked:
                in_mem_text = "yes" if in_memory else "no"
                if not in_memory:
                    total_out_of_mem += 1

            if not parse_ok:
                status = "ERR_PARSE"
                is_invalid = True
            elif not in_a2l:
                status = "NOT_IN_A2L"
                is_invalid = True
            elif memory_checked and in_memory is False:
                status = "OUT_OF_IMAGE"
                is_invalid = True
            else:
                status = "OK"
                is_invalid = False

            if is_invalid:
                total_invalid += 1
            else:
                total_valid += 1

            addr_text = f"0x{address:08X}" if isinstance(address, int) else "n/a"
            rows.append(
                (
                    name or "(invalid)",
                    addr_text,
                    "yes" if in_a2l else "no",
                    in_mem_text,
                    status,
                    str(line_no),
                    parse_error,
                    a2l_match_text,
                )
            )
            row_meta.append(
                {
                    "is_invalid": is_invalid,
                    "address": address if isinstance(address, int) else None,
                }
            )

        name_width = min(48, max(len("Tag"), *(len(row[0]) for row in rows)))
        addr_width = max(len("Address"), *(len(row[1]) for row in rows))
        in_a2l_width = max(len("InA2L"), *(len(row[2]) for row in rows))
        in_mem_width = max(len("InMem"), *(len(row[3]) for row in rows))
        status_width = max(len("Status"), *(len(row[4]) for row in rows))
        line_width = max(len("SourceLine"), *(len(row[5]) for row in rows))
        parse_width = min(36, max(len("ParseErr"), *(len(row[6]) for row in rows)))
        match_width = min(36, max(len("A2LMatch"), *(len(row[7]) for row in rows)))

        header = (
            f"{'Tag'.ljust(name_width)} | {'Address'.ljust(addr_width)} | "
            f"{'InA2L'.ljust(in_a2l_width)} | {'InMem'.ljust(in_mem_width)} | "
            f"{'Status'.ljust(status_width)} | {'SourceLine'.ljust(line_width)} | "
            f"{'ParseErr'.ljust(parse_width)} | {'A2LMatch'.ljust(match_width)}"
        )
        mac_list.append(ListItem(Label(header)))

        for index, row in enumerate(rows):
            line = (
                f"{row[0][:name_width].ljust(name_width)} | {row[1].ljust(addr_width)} | "
                f"{row[2].ljust(in_a2l_width)} | {row[3].ljust(in_mem_width)} | "
                f"{row[4].ljust(status_width)} | {row[5].ljust(line_width)} | "
                f"{row[6][:parse_width].ljust(parse_width)} | {row[7][:match_width].ljust(match_width)}"
            )
            label = Label(line)
            if row_meta[index]["is_invalid"]:
                label.add_class("invalid")
            else:
                label.add_class("valid")
            item = ListItem(label)
            item.data = {"address": row_meta[index]["address"]}
            mac_list.append(item)

        summary = (
            f"Total={len(records)}  Valid={total_valid}  Invalid={total_invalid}  "
            f"InA2L={total_in_a2l}  OutOfMem={total_out_of_mem}  ParseErrs={total_parse_errors}"
        )
        mac_list.append(ListItem(Label(summary)))

    def update_a2l_view(self) -> None:
        """Render the A2L summary view."""
        a2l_view = self.query_one("#a2l_view", Static)
        if not self.current_a2l_data:
            a2l_view.update("No A2L loaded.")
            self.update_a2l_tags_view([])
            self.update_mac_view()
            return
        mem_map = self.current_file.mem_map if self.current_file else None
        tag_checks = validate_a2l_tags(self.current_a2l_data.get("tags", []), mem_map)
        a2l_view.update(render_a2l_view(self.current_a2l_data, tag_checks))
        tags = self.current_a2l_data.get("tags", [])
        check_map = {(t.get("section"), t.get("name")): t for t in tag_checks}
        enriched = []
        for tag in tags:
            key = (tag.get("section"), tag.get("name"))
            enriched.append({**tag, **check_map.get(key, {})})
        tags = enriched
        filter_input = self.query_one("#a2l_tags_filter_input", Input)
        self.a2l_tags_filter_text = filter_input.value.strip()
        tags = self._filter_a2l_tags(tags)
        self.update_a2l_tags_view(tags)
        self.update_mac_view()

    def update_a2l_tags_view(self, tags: list[dict]) -> None:
        a2l_tags_list = self.query_one("#a2l_tags_list", ListView)
        a2l_tags_list.clear()
        if not tags:
            a2l_tags_list.append(ListItem(Label("No A2L tags.")))
            return
        rows: list[tuple] = []
        row_tags: list[dict] = []
        for tag in tags:
            addr = tag.get("address")
            length = tag.get("length")
            addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
            len_text = str(length) if isinstance(length, int) else "n/a"
            name_text = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
            source_text = str(tag.get("source") or "assigned")
            in_mem_text = _a2l_tag_in_memory_display(tag)
            region_text = str(tag.get("memory_region") or "unknown")
            limits_text = ""
            if tag.get("lower_limit") is not None or tag.get("upper_limit") is not None:
                limits_text = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
            unit_text = str(tag.get("unit") or "")
            bit_text = str(tag.get("bit_org") or "")
            endian_text = str(tag.get("endian") or "")
            virt_text = "yes" if tag.get("virtual") else "no"
            func_text = str(tag.get("function_group") or "")
            access_text = str(tag.get("access") or "")
            dtype_text = str(tag.get("datatype") or "")
            rows.append(
                (
                    name_text,
                    addr_text,
                    len_text,
                    source_text,
                    in_mem_text,
                    region_text,
                    limits_text,
                    unit_text,
                    bit_text,
                    endian_text,
                    virt_text,
                    func_text,
                    access_text,
                    dtype_text,
                )
            )
            row_tags.append(tag)

        name_width = min(48, max(len("Tag"), *(len(row[0]) for row in rows)))
        addr_width = max(len("Address"), *(len(row[1]) for row in rows))
        len_width = max(len("Length"), *(len(row[2]) for row in rows))
        source_width = max(len("Source"), *(len(row[3]) for row in rows))
        mem_width = max(len("InMem"), *(len(row[4]) for row in rows))
        region_width = max(len("Region"), *(len(row[5]) for row in rows))
        limits_width = max(len("Limits"), *(len(row[6]) for row in rows))
        unit_width = max(len("Unit"), *(len(row[7]) for row in rows))
        bit_width = max(len("Bits"), *(len(row[8]) for row in rows))
        endian_width = max(len("Endian"), *(len(row[9]) for row in rows))
        virt_width = max(len("Virt"), *(len(row[10]) for row in rows))
        func_width = max(len("Func"), *(len(row[11]) for row in rows))
        access_width = max(len("Access"), *(len(row[12]) for row in rows))
        dtype_width = max(len("Dtype"), min(12, max((len(row[13]) for row in rows), default=0)))

        header = (
            f"{'Tag'.ljust(name_width)} | {'Address'.ljust(addr_width)} | "
            f"{'Length'.ljust(len_width)} | {'Source'.ljust(source_width)} | "
            f"{'InMem'.ljust(mem_width)} | {'Region'.ljust(region_width)} | "
            f"{'Limits'.ljust(limits_width)} | {'Unit'.ljust(unit_width)} | "
            f"{'Bits'.ljust(bit_width)} | {'Endian'.ljust(endian_width)} | "
            f"{'Virt'.ljust(virt_width)} | {'Func'.ljust(func_width)} | "
            f"{'Access'.ljust(access_width)} | {'Dtype'.ljust(dtype_width)}"
        )
        a2l_tags_list.append(ListItem(Label(header)))
        for i, row in enumerate(rows):
            name_text = row[0][:name_width].ljust(name_width)
            line = (
                f"{name_text} | {row[1].ljust(addr_width)} | {row[2].ljust(len_width)} | "
                f"{row[3].ljust(source_width)} | {row[4].ljust(mem_width)} | "
                f"{row[5].ljust(region_width)} | {row[6].ljust(limits_width)} | "
                f"{row[7].ljust(unit_width)} | {row[8].ljust(bit_width)} | "
                f"{row[9].ljust(endian_width)} | {row[10].ljust(virt_width)} | "
                f"{row[11].ljust(func_width)} | {row[12].ljust(access_width)} | "
                f"{row[13][:dtype_width].ljust(dtype_width)}"
            )
            label = Label(line)
            if _a2l_tag_row_invalid(row_tags[i]):
                label.add_class("invalid")
            item = ListItem(label)
            item.data = {"address": row[1], "name": row[0]}
            if isinstance(row[1], str) and row[1].startswith("0x"):
                try:
                    item.data["address"] = int(row[1], 16)
                except ValueError:
                    pass
            a2l_tags_list.append(item)

    def _filter_a2l_tags(self, tags: list[dict]) -> list[dict]:
        mode = self.a2l_tags_filter_mode
        text = (self.a2l_tags_filter_text or "").lower()
        filtered = []
        for tag in tags:
            if mode == "invalid":
                show = (not tag.get("schema_ok", True)) or (
                    tag.get("memory_checked") and tag.get("in_memory") is False
                )
                if not show:
                    continue
            if mode == "inmem" and tag.get("in_memory") is not True:
                continue
            if text:
                if not self._tag_matches_filter(tag, text):
                    continue
            filtered.append(tag)
        return filtered

    def _tag_matches_filter(self, tag: dict, text: str) -> bool:
        field = self.a2l_tags_filter_field
        if field == "all":
            haystack = " ".join(
                [
                    str(tag.get("name") or ""),
                    str(tag.get("address") or ""),
                    str(tag.get("length") or ""),
                    str(tag.get("source") or ""),
                    _a2l_tag_in_memory_display(tag),
                    str(tag.get("lower_limit") or ""),
                    str(tag.get("upper_limit") or ""),
                    str(tag.get("unit") or ""),
                    str(tag.get("bit_org") or ""),
                    str(tag.get("endian") or ""),
                    str(tag.get("virtual") or ""),
                    str(tag.get("function_group") or ""),
                    str(tag.get("access") or ""),
                    str(tag.get("datatype") or ""),
                    str(tag.get("description") or ""),
                    str(tag.get("memory_region") or ""),
                ]
            ).lower()
            return text in haystack

        value = ""
        if field == "name":
            value = str(tag.get("name") or "")
        elif field == "address":
            value = str(tag.get("address") or "")
        elif field == "length":
            value = str(tag.get("length") or "")
        elif field == "source":
            value = str(tag.get("source") or "")
        elif field == "in_memory":
            value = _a2l_tag_in_memory_display(tag)
        elif field == "limits":
            value = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
        elif field == "unit":
            value = str(tag.get("unit") or "")
        elif field == "bits":
            value = str(tag.get("bit_org") or "")
        elif field == "endian":
            value = str(tag.get("endian") or "")
        elif field == "virtual":
            value = "yes" if tag.get("virtual") else "no"
        elif field == "function_group":
            value = str(tag.get("function_group") or "")
        elif field == "access":
            value = str(tag.get("access") or "")
        elif field == "datatype":
            value = str(tag.get("datatype") or "")
        elif field == "description":
            value = str(tag.get("description") or "")
        elif field == "memory_region":
            value = str(tag.get("memory_region") or "")
        return text in value.lower()

    def _toggle_a2l_filter_menu(self) -> None:
        menu = self.query_one("#a2l_filter_menu")
        if "hidden" in menu.classes:
            self._update_a2l_filter_menu()
            menu.remove_class("hidden")
        else:
            menu.add_class("hidden")

    def _update_a2l_filter_menu(self) -> None:
        menu_list = self.query_one("#a2l_filter_menu_list", ListView)
        menu_list.clear()
        for field in self.a2l_tags_filter_fields:
            label = f"(*) {field}" if field == self.a2l_tags_filter_field else f"( ) {field}"
            item = ListItem(Label(label))
            item.data = field
            menu_list.append(item)

    def _set_a2l_filter_field(self, field: str) -> None:
        if field not in self.a2l_tags_filter_fields:
            return
        self.a2l_tags_filter_field = field
        button = self.query_one("#a2l_filter_field", Button)
        button.label = f"Field: {field}"
        menu = self.query_one("#a2l_filter_menu")
        menu.add_class("hidden")
        self._update_a2l_filter_menu()
        self.update_a2l_view()

    def update_project_labels(self) -> None:
        """Refresh project/A2L labels in the status tile."""
        project_label = self.query_one("#project_text", Label)
        a2l_label = self.query_one("#a2l_text", Label)
        project_label.update(f"Project: {self.current_project or '(none)'}")
        a2l_name = self.current_a2l_path.name if self.current_a2l_path else "(none)"
        a2l_label.update(f"A2L: {a2l_name}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "search_button":
            self._handle_search()
        elif event.button.id == "goto_button":
            self._handle_goto()
        elif event.button.id == "view_hex_button":
            self.action_view_main()
        elif event.button.id == "view_a2l_button":
            self.action_view_alt()
        elif event.button.id == "view_mac_button":
            self.action_view_mac()
        elif event.button.id == "alt_search_button":
            self._handle_search_alt()
        elif event.button.id == "alt_goto_button":
            self._handle_goto_alt()
        elif event.button.id == "mac_search_button":
            self._handle_search_mac()
        elif event.button.id == "mac_goto_button":
            self._handle_goto_mac()
        elif event.button.id == "a2l_filter_all":
            self.a2l_tags_filter_mode = "all"
            self.update_a2l_view()
        elif event.button.id == "a2l_filter_invalid":
            self.a2l_tags_filter_mode = "invalid"
            self.update_a2l_view()
        elif event.button.id == "a2l_filter_inmem":
            self.a2l_tags_filter_mode = "inmem"
            self.update_a2l_view()
        elif event.button.id == "a2l_filter_field":
            self._toggle_a2l_filter_menu()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "a2l_tags_filter_input":
            self.a2l_tags_filter_text = event.value.strip()
            self.update_a2l_view()

    def _handle_search(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        if self.last_search_text != query:
            self.last_search_text = query
            self.last_search_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1

        addr = find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_hex_view(addr)
        self.set_status(f"Found at 0x{addr:08X}")

    def _handle_goto(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            return
        self.update_hex_view(addr)
        self.set_status(f"Goto 0x{addr:08X}")

    def _handle_search_alt(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#alt_search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        if self.last_search_text != query:
            self.last_search_text = query
            self.last_search_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1

        addr = find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_alt_hex_view(addr)
        self.set_status(f"Found at 0x{addr:08X}")

    def _handle_goto_alt(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#alt_goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            return
        self.update_alt_hex_view(addr)
        self.set_status(f"Goto 0x{addr:08X}")

    def _handle_search_mac(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#mac_search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        if self.last_search_text != query:
            self.last_search_text = query
            self.last_search_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1

        addr = find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_mac_hex_view(addr)
        self.set_status(f"Found at 0x{addr:08X}")

    def _handle_goto_mac(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#mac_goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            return
        self.update_mac_hex_view(addr)
        self.set_status(f"Goto 0x{addr:08X}")

    def set_status(self, message: str) -> None:
        self._append_log_line(message)

    def set_file_status(self, message: str) -> None:
        """Update the first status line reserved for file state."""
        status_text = self.query_one("#status_text", Label)
        status_text.update(message)

    def _append_log_line(self, message: str) -> None:
        trimmed = message.strip()
        if not trimmed:
            return
        line = trimmed[:50]
        self.log_lines.append(line)
        self._render_log_lines()

    def _render_log_lines(self) -> None:
        lines = list(self.log_lines)
        while len(lines) < 4:
            lines.insert(0, "")
        self.query_one("#log_line_1", Label).update(lines[-4])
        self.query_one("#log_line_2", Label).update(lines[-3])
        self.query_one("#log_line_3", Label).update(lines[-2])
        self.query_one("#log_line_4", Label).update(lines[-1])

    def set_progress(self, value: int, message: Optional[str] = None) -> None:
        bar = self.query_one("#progress_bar", ProgressBar)
        bar.update(total=100, progress=max(0, min(100, value)))
        if message:
            self.set_status(message)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="S19/HEX/MAC TUI Viewer")
    parser.add_argument("--load", help="Optional path to load at startup")
    args = parser.parse_args()
    load_path = Path(args.load) if args.load else None
    app = S19TuiApp(load_path=load_path)
    app.run()
