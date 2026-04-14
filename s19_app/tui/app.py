from __future__ import annotations

from collections import deque
import json
from pathlib import Path
import time
from typing import Any, List, Optional

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
from .a2l import parse_a2l_file, render_a2l_view, validate_a2l_internal_issues, validate_a2l_tags
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
from .screens import LoadFileScreen, LoadProjectScreen, SaveProjectPayload, SaveProjectScreen
from .color_policy import css_class_for_severity
from ..validation import ValidationIssue, ValidationReport, ValidationSeverity, validate_artifact_consistency
from .workspace import (
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
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


def _a2l_tag_row_severity(tag: dict) -> ValidationSeverity:
    if not tag.get("schema_ok", True):
        return ValidationSeverity.ERROR
    if bool(tag.get("memory_checked") and tag.get("in_memory") is False):
        return ValidationSeverity.ERROR
    if tag.get("memory_checked") and tag.get("in_memory") is True:
        return ValidationSeverity.OK
    return ValidationSeverity.NEUTRAL


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


def _mac_record_ui_state(
    record: dict[str, Any],
    a2l_name_index: dict[str, list[dict]],
    has_a2l: bool,
    memory_checked: bool,
    in_memory: Optional[bool],
) -> tuple[str, str]:
    """
    Summary:
        Derive MAC table status text and CSS class for one parsed ``.mac`` record.

    Args:
        record (dict[str, Any]): Parser record with ``parse_ok``, ``name``, ``address``, etc.
        a2l_name_index (dict[str, list[dict]]): Map of lowercased A2L tag name to tag dicts.
        has_a2l (bool): Whether an A2L dataset is loaded for cross-check.
        memory_checked (bool): True when an S19/HEX image is available for address membership.
        in_memory (Optional[bool]): Image membership when ``memory_checked`` is True.

    Returns:
        tuple[str, str]: ``(status, css_class)`` where ``css_class`` is ``invalid``, ``valid``,
        or ``neutral`` (default terminal color; no green/red).

    Data Flow:
        - Fail parse and out-of-image rows to invalid.
        - When A2L is absent or the tag name is missing, mark neutral.
        - When the name is absent from A2L, mark neutral.
        - When the name exists, require a matching ECU address on some A2L tag for ``valid``.

    Dependencies:
        Used by:
            - ``S19TuiApp.update_mac_view``
    """
    if not record.get("parse_ok"):
        return "ERR_PARSE", ValidationSeverity.ERROR.value
    name = str(record.get("name") or "").strip()
    address = record.get("address")
    if memory_checked and in_memory is False:
        return "OUT_OF_IMAGE", ValidationSeverity.ERROR.value
    if not has_a2l or not name:
        return "NO_A2L", ValidationSeverity.NEUTRAL.value
    matches = a2l_name_index.get(name.lower(), [])
    if not matches:
        return "NOT_IN_A2L", ValidationSeverity.WARNING.value
    if not isinstance(address, int):
        return "NO_ADDR", ValidationSeverity.ERROR.value
    for tag in matches:
        tag_addr = tag.get("address")
        if isinstance(tag_addr, int) and tag_addr == address:
            return "OK", ValidationSeverity.OK.value
    return "A2L_ADDR_MISMATCH", ValidationSeverity.ERROR.value


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

    #a2l_tag_find_input {
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


    .sev-ok {
        color: green;
    }

    .sev-error {
        color: red;
    }

    .sev-warning {
        color: orange1;
    }

    .sev-info {
        color: cyan;
    }

    .sev-neutral {
        color: grey70;
    }

    .mac_out_of_range {
        color: orange;
    }

    #validation_issues_filters {
        layout: horizontal;
        height: auto;
        padding-top: 1;
    }

    #validation_issues_list {
        height: 12;
        border: round $primary;
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
        ("+", "a2l_tags_page_next", "Tags+"),
        ("-", "a2l_tags_page_prev", "Tags-"),
        ("ctrl+right_square_bracket", "a2l_tags_page_next", "Tags next"),
        ("ctrl+left_square_bracket", "a2l_tags_page_prev", "Tags prev"),
        ("comma", "mac_records_page_prev", "MAC-"),
        ("period", "mac_records_page_next", "MAC+"),
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
    large_a2l_warn_bytes: int = 2 * 1024 * 1024
    slow_parse_warn_seconds: float = 2.5
    a2l_window_size: int = 300
    a2l_window_overscan: int = 80
    a2l_tags_page_size: int = 200
    mac_records_page_size: int = 200
    a2l_summary_window_size: int = 500
    a2l_tag_hex_highlight_max_bytes: int = 4096
    validation_issue_filter_mode: str = "all"

    def __init__(self, base_dir: Optional[Path] = None, load_path: Optional[Path] = None):
        super().__init__()
        self.base_dir = base_dir or Path.cwd()
        self.logger = setup_logging(self.base_dir)
        self.workarea = ensure_workarea(self.base_dir)
        self.load_path = load_path
        self.log_lines = deque(maxlen=4)
        self._a2l_cache_key: Optional[tuple[str, int, int]] = None
        self._a2l_cache_data: Optional[dict[str, Any]] = None
        self._a2l_enriched_tags: list[dict[str, Any]] = []
        self._a2l_enriched_key: Optional[tuple[int, int]] = None
        self._a2l_filtered_tags: list[dict[str, Any]] = []
        self._a2l_window_start: int = 0
        self._a2l_summary_lines: list[str] = []
        self._a2l_summary_start: int = 0
        self._a2l_filter_debounce_token: int = 0
        self._a2l_tag_hex_highlight: Optional[tuple[int, int]] = None
        self._a2l_tag_find_query: str = ""
        self._a2l_tag_find_last_index: int = -1
        self._validation_report: Optional[ValidationReport] = None
        self._validation_issues: list[ValidationIssue] = []
        self.current_project_dir: Optional[Path] = None
        self._mac_window_start: int = 0
        self.logger.info("App initialized. base_dir=%s workarea=%s", self.base_dir, self.workarea)

    def _debug_log(self, run_id: str, hypothesis_id: str, location: str, message: str, data: dict[str, Any]) -> None:
        # region agent log
        try:
            payload = {
                "sessionId": "cdc3df",
                "runId": run_id,
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "data": data,
                "timestamp": int(time.time() * 1000),
            }
            with (self.base_dir / "debug-cdc3df.log").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception:
            pass
        # endregion

    def _get_window_bounds(self, total: int, start: int, window_size: int) -> tuple[int, int]:
        """
        Summary:
            Clamp a requested window start and return a safe half-open render range.

        Args:
            total (int): Total available rows/lines.
            start (int): Requested window start index.
            window_size (int): Number of rows/lines to render in one window.

        Returns:
            tuple[int, int]: ``(start, end)`` bounds clamped to ``[0, total]``.

        Data Flow:
            - Clamp ``start`` to a valid source index.
            - Compute ``end`` from clamped start plus window size.
            - Clamp ``end`` to source length.

        Dependencies:
            Uses:
                - built-in ``max`` / ``min`` arithmetic
            Used by:
                - A2L tags and summary buffered render helpers
        """
        if total <= 0:
            return 0, 0
        safe_start = max(0, min(start, total - 1))
        safe_end = min(total, safe_start + max(1, window_size))
        return safe_start, safe_end

    def _a2l_clamp_page_start(self, total_tags: int) -> int:
        """
        Summary:
            Clamp ``_a2l_window_start`` to a legal page-aligned index for the A2L tags table.

        Args:
            total_tags (int): Number of rows in ``_a2l_filtered_tags``.

        Returns:
            int: Page-aligned start index in ``[0, total_tags)`` (or ``0`` when empty).

        Data Flow:
            - Align the current start down to ``a2l_tags_page_size`` boundaries.
            - Clamp to the last valid page start when the list shrinks.

        Dependencies:
            Used by:
                - ``update_a2l_tags_view``
                - ``_refresh_a2l_filtered_tags``
        """
        ps = self.a2l_tags_page_size
        if total_tags <= 0 or ps <= 0:
            return 0
        aligned = (max(0, self._a2l_window_start) // ps) * ps
        max_start = max(0, ((total_tags - 1) // ps) * ps)
        return max(0, min(aligned, max_start))

    def _mac_clamp_page_start(self, total_records: int) -> int:
        """
        Summary:
            Clamp ``_mac_window_start`` to a legal page start for MAC record paging.

        Args:
            total_records (int): Number of parsed MAC records.

        Returns:
            int: Page-aligned start index in ``[0, total_records)`` (or ``0`` when empty).

        Data Flow:
            - Align the current MAC window start to ``mac_records_page_size`` boundaries.
            - Clamp to the last legal page when the list shrinks.

        Dependencies:
            Used by:
                - ``update_mac_view``
                - MAC page navigation actions
        """
        ps = max(1, self.mac_records_page_size)
        if total_records <= 0 or ps <= 0:
            return 0
        aligned = (max(0, self._mac_window_start) // ps) * ps
        max_start = max(0, ((total_records - 1) // ps) * ps)
        return max(0, min(aligned, max_start))

    def _active_project_dir(self) -> Optional[Path]:
        """
        Summary:
            Return the absolute directory for the active saved project, if any.

        Args:
            None

        Returns:
            Optional[Path]: Resolved project folder, or ``None`` when no project is active.

        Data Flow:
            - Prefer ``current_project_dir`` when set (external or explicit path).
            - Fall back to ``workarea / current_project`` for workarea-only projects.

        Dependencies:
            Used by:
                - A2L/data sync helpers
                - ``load_a2l_from_path`` project guard
        """
        if self.current_project_dir is not None:
            return self.current_project_dir
        if self.current_project:
            return (self.workarea / self.current_project).resolve()
        return None

    def _shift_window_for_index(self, total: int, index: int, start: int, window_size: int) -> int:
        """
        Summary:
            Shift a window start so a selected/highlighted absolute index stays within buffered margins.

        Args:
            total (int): Total source rows.
            index (int): Absolute row index that should remain in the buffered viewport.
            start (int): Current window start index.
            window_size (int): Number of rows rendered in one window.

        Returns:
            int: Updated window start index.

        Data Flow:
            - Compute current window bounds.
            - If index is near top/bottom overscan thresholds, move start forward/backward.
            - Clamp final start to source range.

        Dependencies:
            Uses:
                - ``_get_window_bounds``
            Used by:
                - A2L tags selection/highlight handlers
        """
        if total <= 0:
            return 0
        index = max(0, min(index, total - 1))
        current_start, current_end = self._get_window_bounds(total, start, window_size)
        top_threshold = current_start + self.a2l_window_overscan
        bottom_threshold = current_end - self.a2l_window_overscan
        if index < top_threshold:
            new_start = max(0, index - self.a2l_window_overscan)
            return new_start
        if index >= bottom_threshold:
            new_start = max(0, index - (window_size - self.a2l_window_overscan - 1))
            return min(new_start, max(0, total - window_size))
        return current_start

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
                Container(
                    Button("Issues: All", id="issues_filter_all"),
                    Button("Errors", id="issues_filter_error"),
                    Button("Warnings", id="issues_filter_warning"),
                    id="validation_issues_filters",
                ),
                ListView(id="validation_issues_list"),
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
                    Input(placeholder="Find in tag table", id="a2l_tag_find_input"),
                    Button("Find next", id="a2l_tag_find_next"),
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
        self.update_validation_issues_view()
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
        self.push_screen(SaveProjectScreen(self.workarea), self._handle_save_dialog)

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

    def action_a2l_tags_page_next(self) -> None:
        """
        Summary:
            Advance the A2L tags table by one page of ``a2l_tags_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bump ``_a2l_window_start`` by one page and clamp to the last legal page start.
            - Re-render the current filtered tag slice.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
        """
        total = len(self._a2l_filtered_tags)
        if total <= 0:
            return
        page_size = max(1, self.a2l_tags_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._a2l_window_start = min(max_start, self._a2l_window_start + page_size)
        self.update_a2l_tags_view(self._a2l_filtered_tags)

    def action_a2l_tags_page_prev(self) -> None:
        """
        Summary:
            Move the A2L tags table back by one page of ``a2l_tags_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Decrement ``_a2l_window_start`` by one page and clamp at zero.
            - Re-render the current filtered tag slice.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
        """
        if not self._a2l_filtered_tags:
            return
        page_size = max(1, self.a2l_tags_page_size)
        self._a2l_window_start = max(0, self._a2l_window_start - page_size)
        self.update_a2l_tags_view(self._a2l_filtered_tags)

    def action_mac_records_page_next(self) -> None:
        """
        Summary:
            Advance the MAC records table by one page of ``mac_records_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bump ``_mac_window_start`` by one page and clamp to the last legal page start.
            - Re-render the MAC list.

        Dependencies:
            Uses:
                - ``update_mac_view``
        """
        if not self.current_file:
            return
        records = self.current_file.mac_records or []
        total = len(records)
        if total <= 0:
            return
        page_size = max(1, self.mac_records_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._mac_window_start = min(max_start, self._mac_window_start + page_size)
        self.update_mac_view()

    def action_mac_records_page_prev(self) -> None:
        """
        Summary:
            Move the MAC records table back by one page of ``mac_records_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Decrement ``_mac_window_start`` by one page and clamp at zero.
            - Re-render the MAC list.

        Dependencies:
            Uses:
                - ``update_mac_view``
        """
        if not self.current_file:
            return
        records = self.current_file.mac_records or []
        if not records:
            return
        page_size = max(1, self.mac_records_page_size)
        self._mac_window_start = max(0, self._mac_window_start - page_size)
        self.update_mac_view()

    def action_a2l_tag_find_next(self) -> None:
        """Invoke the A2L tag find-next scan (same as the Find-next button)."""
        self._handle_a2l_tag_find_next()

    def _handle_save_dialog(self, payload: Optional[SaveProjectPayload]) -> None:
        if payload is None:
            self.logger.info("Save project canceled.")
            return
        if not self.current_file and not self.current_a2l_path:
            self.set_status("Nothing to save: load a data file or A2L first.")
            self.logger.info("Save project dismissed: no loaded file or A2L.")
            return
        parent_resolved = resolve_input_path(Path(payload.parent_folder), self.base_dir)
        if not parent_resolved or not parent_resolved.is_dir():
            self.set_status("Parent folder not found or not a directory.")
            self.logger.warning("Invalid parent folder: %s", payload.parent_folder)
            return
        cleaned = sanitize_project_name(payload.project_name)
        if not cleaned:
            self.set_status("Invalid project name.")
            self.logger.warning("Invalid project name: %s", payload.project_name)
            return
        project_dir = (parent_resolved / cleaned).resolve()
        project_dir.mkdir(parents=True, exist_ok=True)
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.set_status(error)
            self.logger.warning("Project validation failed: %s", error)
            return
        existing_suffixes = {item.suffix.lower() for item in data_files}
        if self.current_file and self.current_file.path.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS:
            has_primary = any(sfx in PROJECT_PRIMARY_DATA_EXTENSIONS for sfx in existing_suffixes)
            if has_primary and self.current_file.path.suffix.lower() not in existing_suffixes:
                self.set_status("Project already has an S19/HEX file.")
                self.logger.warning("Project already has primary data file: %s", project_dir)
                return
        if self.current_file and self.current_file.mac_path:
            has_mac = ".mac" in existing_suffixes
            if has_mac and self.current_file.mac_path.name not in {item.name for item in data_files}:
                self.set_status("Project already has a MAC file.")
                self.logger.warning("Project already has MAC file: %s", project_dir)
                return
        if a2l_files and self.current_a2l_path and self.current_a2l_path.suffix.lower() in A2L_EXTENSIONS:
            self.set_status("Project already has an A2L file.")
            self.logger.warning("Project already has A2L file: %s", project_dir)
            return
        if self.current_file:
            saved = copy_into_workarea(self.current_file.path, project_dir)
            self.logger.info("Project saved. name=%s file=%s", cleaned, saved)
            if self.current_file.mac_path and self.current_file.mac_path != self.current_file.path:
                saved_mac = copy_into_workarea(self.current_file.mac_path, project_dir)
                self.logger.info("Project saved MAC. name=%s file=%s", cleaned, saved_mac)
        if self.current_a2l_path:
            saved_a2l = copy_into_workarea(self.current_a2l_path, project_dir)
            self.logger.info("Project saved A2L. name=%s file=%s", cleaned, saved_a2l)
        self.current_project = cleaned
        self.current_project_dir = project_dir
        self.set_status(f"Saved project to {project_dir}")
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
        primary_file = next((item for item in data_files if item.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS), None)
        mac_file = next((item for item in data_files if item.suffix.lower() in MAC_EXTENSIONS), None)
        selected_file = primary_file or mac_file
        if selected_file is None:
            self.set_status(f"No supported files in project: {name}")
            self.logger.warning("No loadable data file in project: %s", name)
            return
        self.current_project = name
        self.current_project_dir = project_dir.resolve()
        self.load_selected_file(selected_file, a2l_files)
        if primary_file and mac_file:
            self.load_selected_file(mac_file, a2l_files)
        status_target = f"{selected_file.name} + {mac_file.name}" if primary_file and mac_file else selected_file.name
        self.set_status(f"Loaded project '{name}' -> {status_target}")
        self.logger.info("Project loaded. name=%s file=%s mac=%s", name, selected_file, mac_file)
        self.update_project_labels()

    def list_projects(self) -> List[str]:
        projects = []
        for item in sorted(self.workarea.iterdir()):
            if item.is_dir() and item.name != WORKAREA_TEMP:
                projects.append(item.name)
        return projects

    def _sync_loaded_file_to_project(self) -> None:
        """Copy loaded data file into active project if allowed."""
        if not self.current_file:
            return
        project_dir = self._active_project_dir()
        if not project_dir:
            return
        project_dir.mkdir(parents=True, exist_ok=True)
        data_files, a2l_files, error = validate_project_files(project_dir)
        if error:
            self.logger.warning("Project validation failed during sync: %s", error)
            return
        if data_files:
            existing_suffixes = {item.suffix.lower() for item in data_files}
        else:
            existing_suffixes = set()
        if self.current_file.path.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS:
            if not any(sfx in PROJECT_PRIMARY_DATA_EXTENSIONS for sfx in existing_suffixes):
                copy_into_workarea(self.current_file.path, project_dir)
                self.logger.info("Synced primary data file into project: %s", project_dir)
        elif self.current_file.path.suffix.lower() in MAC_EXTENSIONS and ".mac" not in existing_suffixes:
            copy_into_workarea(self.current_file.path, project_dir)
            self.logger.info("Synced MAC data file into project: %s", project_dir)
        if (
            self.current_file.mac_path
            and self.current_file.mac_path != self.current_file.path
            and self.current_file.mac_path.suffix.lower() in MAC_EXTENSIONS
            and ".mac" not in existing_suffixes
        ):
            copy_into_workarea(self.current_file.mac_path, project_dir)
            self.logger.info("Synced attached MAC file into project: %s", project_dir)

    def _sync_loaded_a2l_to_project(self) -> None:
        """Copy loaded A2L file into active project if allowed."""
        if not self.current_a2l_path:
            return
        project_dir = self._active_project_dir()
        if not project_dir:
            return
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
        self.logger.info("DBG H4 path resolution: input=%s resolved=%s", path, normalized)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H4",
            location="s19_app/tui/app.py:_load_path_from_user_input",
            message="Resolved path for load",
            data={
                "input_path": str(path),
                "resolved_path": str(normalized) if normalized else None,
                "suffix": normalized.suffix.lower() if normalized else None,
            },
        )
        # endregion
        if not normalized:
            self.set_status(f"File not found: {path}")
            self.logger.warning("File not found: %s", path)
            return
        suffix = normalized.suffix.lower()
        if suffix in A2L_EXTENSIONS:
            self.load_a2l_from_path(path)
            self.logger.info("DBG H4 returned from load_a2l_from_path: resolved=%s", normalized)
            # region agent log
            self._debug_log(
                run_id="initial",
                hypothesis_id="H4",
                location="s19_app/tui/app.py:_load_path_from_user_input",
                message="Returned from load_a2l_from_path",
                data={"resolved_path": str(normalized)},
            )
            # endregion
        elif suffix in SUPPORTED_EXTENSIONS:
            self.load_from_path(path)
        else:
            self.set_status(f"Unsupported file type: {normalized.suffix}")
            self.logger.warning("Unsupported file type: %s", normalized.suffix)

    def _handle_load_dialog(self, path: Optional[Path]) -> None:
        self.logger.info("DBG H4 load dialog callback entry: path=%s", path)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H4",
            location="s19_app/tui/app.py:_handle_load_dialog",
            message="Entered load dialog callback",
            data={"path_is_none": path is None, "path": str(path) if path else None},
        )
        # endregion
        if path is None:
            return
        self._load_path_from_user_input(path)
        self.logger.info("DBG H4 load dialog callback exit: path=%s", path)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H4",
            location="s19_app/tui/app.py:_handle_load_dialog",
            message="Completed load dialog callback",
            data={"path": str(path)},
        )
        # endregion

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
        copy_started = time.perf_counter()
        copied = copy_into_workarea(normalized, temp_dir)
        copy_elapsed = time.perf_counter() - copy_started
        self.refresh_files()
        self.set_progress(50, f"Loading {copied.name}...")
        self.logger.info(
            "File copied to temp: path=%s size_bytes=%d copy_seconds=%.3f",
            copied,
            copied.stat().st_size,
            copy_elapsed,
        )
        self.load_selected_file(copied)
        self.set_progress(100, f"Loaded {copied.name}")

        if self.current_project:
            self._sync_loaded_file_to_project()

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
            project_dir = self._active_project_dir()
            if project_dir:
                _, a2l_files, error = validate_project_files(project_dir)
                if error:
                    self.set_status(error)
                    self.logger.warning("Project validation failed: %s", error)
                    return
                if a2l_files:
                    self.set_status("Project already has an A2L file.")
                    self.logger.warning("Project already has A2L file: %s", project_dir)
                    return
            else:
                self.logger.warning("current_project set but project directory could not be resolved; skipping project guard.")
        temp_dir = self.workarea / WORKAREA_TEMP
        source_size = normalized.stat().st_size
        if source_size >= self.large_a2l_warn_bytes:
            self.logger.warning(
                "Large A2L detected before copy: path=%s size_bytes=%d threshold_bytes=%d",
                normalized,
                source_size,
                self.large_a2l_warn_bytes,
            )
        self.set_progress(10, "Copying A2L into workarea temp...")
        copy_started = time.perf_counter()
        copied = copy_into_workarea(normalized, temp_dir)
        copy_elapsed = time.perf_counter() - copy_started
        self.refresh_files()
        copied_size = copied.stat().st_size
        self.logger.info(
            "A2L copy complete: path=%s size_bytes=%d copy_seconds=%.3f",
            copied,
            copied_size,
            copy_elapsed,
        )
        self.set_progress(50, f"Parsing {copied.name}...")
        self.current_a2l_path = copied
        parse_started = time.perf_counter()
        self.current_a2l_data = self._load_a2l_data_with_cache(copied)
        parse_elapsed = time.perf_counter() - parse_started
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H1",
            location="s19_app/tui/app.py:load_a2l_from_path",
            message="A2L parse stage complete",
            data={
                "path": str(copied),
                "size_bytes": copied_size,
                "parse_elapsed_seconds": round(parse_elapsed, 3),
                "tag_count": len((self.current_a2l_data or {}).get("tags", [])),
                "section_count": len((self.current_a2l_data or {}).get("sections", [])),
            },
        )
        # endregion
        self._log_a2l_parse_summary(copied, self.current_a2l_data, parse_elapsed)
        if self.current_file:
            self.current_file.a2l_path = copied
            self.current_file.a2l_data = self.current_a2l_data
        view_started = time.perf_counter()
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H1",
            location="s19_app/tui/app.py:load_a2l_from_path",
            message="Entering update_a2l_view",
            data={"tag_count": len((self.current_a2l_data or {}).get("tags", []))},
        )
        # endregion
        self.update_a2l_view()
        view_elapsed = time.perf_counter() - view_started
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H1",
            location="s19_app/tui/app.py:load_a2l_from_path",
            message="Finished update_a2l_view",
            data={"view_elapsed_seconds": round(view_elapsed, 3)},
        )
        # endregion
        if view_elapsed > self.slow_parse_warn_seconds:
            self.logger.warning(
                "A2L view refresh was slow: path=%s elapsed_seconds=%.3f threshold_seconds=%.3f",
                copied,
                view_elapsed,
                self.slow_parse_warn_seconds,
            )
        else:
            self.logger.info("A2L view refresh complete: path=%s elapsed_seconds=%.3f", copied, view_elapsed)
        self.update_project_labels()
        self.set_progress(100, f"Loaded {copied.name}")
        self.set_status(f"A2L loaded: {copied.name}")
        self.logger.info("DBG H5 load_a2l_from_path reached completion: path=%s", copied)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H5",
            location="s19_app/tui/app.py:load_a2l_from_path",
            message="A2L load function reached completion",
            data={"path": str(copied)},
        )
        # endregion
        self.logger.info("A2L loaded: %s", copied)

        if self.current_project:
            self._sync_loaded_a2l_to_project()

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
        if event.list_view.id == "validation_issues_list":
            if event.item is None:
                return
            self._jump_to_validation_issue(event.item)
            return

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """
        Summary:
            Reserved for list highlight hooks; A2L tags use explicit page keys instead.

        Args:
            event (ListView.Highlighted): Highlight change event emitted by list views.

        Returns:
            None

        Data Flow:
            - A2L tag paging is driven by ``+`` / ``-`` and find; moving highlight does not repage.

        Dependencies:
            Used by:
                - Textual list highlight event loop
        """
        if event.list_view.id == "a2l_tags_list":
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

    def _a2l_tag_byte_length_for_hex_highlight(self, tag: dict) -> int:
        """
        Summary:
            Choose a byte span for alt-hex highlighting from an A2L tag record.

        Args:
            tag (dict): Enriched tag row including optional integer ``length``.

        Returns:
            int: Positive byte length, capped by ``a2l_tag_hex_highlight_max_bytes``.

        Data Flow:
            - Prefer parsed ``length`` when it is a positive integer.
            - Fall back to a single-byte span when length is unknown.

        Dependencies:
            Used by:
                - ``_jump_to_tag``
                - ``_handle_a2l_tag_find_next``
        """
        raw = tag.get("length")
        if isinstance(raw, int) and raw > 0:
            return min(raw, self.a2l_tag_hex_highlight_max_bytes)
        return 1

    def _jump_to_tag(self, item: ListItem) -> None:
        """
        Summary:
            Focus the alt hex panel on a selected tag address with a byte-range highlight.

        Args:
            item (ListItem): A2L tags table row; ``item.data`` carries ``address`` and ``tag``.

        Returns:
            None

        Data Flow:
            - Read optional integer address and full tag payload from list metadata.
            - Store ``_a2l_tag_hex_highlight`` so ``update_alt_hex_view`` can paint a span.
            - Re-render alt hex centered on the tag address.

        Dependencies:
            Uses:
                - ``_a2l_tag_byte_length_for_hex_highlight``
                - ``update_alt_hex_view``
                - ``set_status``
            Used by:
                - ``on_list_view_selected`` for ``a2l_tags_list``
        """
        tag_info = getattr(item, "data", None)
        if not tag_info:
            return
        if tag_info.get("absolute_index") is None:
            return
        addr = tag_info.get("address")
        if not isinstance(addr, int):
            return
        tag = tag_info.get("tag")
        span = self._a2l_tag_byte_length_for_hex_highlight(tag if isinstance(tag, dict) else {})
        self._a2l_tag_hex_highlight = (addr, span)
        self.update_alt_hex_view(addr)
        self.set_status(f"Tag at 0x{addr:08X}")

    def _focus_a2l_tag_absolute_index(self, absolute_index: int) -> bool:
        """
        Summary:
            Snap the tags table to the page that contains a tag and move list focus to that row.

        Args:
            absolute_index (int): Index into ``_a2l_filtered_tags``.

        Returns:
            bool: True when focus was applied; False when the index is out of range or the list is empty.

        Data Flow:
            - Align ``_a2l_window_start`` to ``(absolute_index // page_size) * page_size``.
            - Rebuild the visible page via ``update_a2l_tags_view``.
            - Set ``ListView.index`` to the summary/header offset plus the in-page row.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
            Used by:
                - ``_handle_a2l_tag_find_next``
        """
        tags = self._a2l_filtered_tags
        total = len(tags)
        if total == 0 or absolute_index < 0 or absolute_index >= total:
            return False
        page_size = max(1, self.a2l_tags_page_size)
        self._a2l_window_start = (absolute_index // page_size) * page_size
        self.update_a2l_tags_view(tags)
        list_view = self.query_one("#a2l_tags_list", ListView)
        row_index = 2 + (absolute_index - self._a2l_window_start)
        list_view.index = row_index
        return True

    def _a2l_tag_find_haystack(self, tag: dict) -> str:
        def _safe(value: Any) -> str:
            return "" if value is None else str(value)

        return " ".join(
            [
                _safe(tag.get("name")),
                _safe(tag.get("address")),
                _safe(tag.get("length")),
                _safe(tag.get("source")),
                _a2l_tag_in_memory_display(tag),
                _safe(tag.get("lower_limit")),
                _safe(tag.get("upper_limit")),
                _safe(tag.get("unit")),
                _safe(tag.get("bit_org")),
                _safe(tag.get("endian")),
                _safe(tag.get("virtual")),
                _safe(tag.get("function_group")),
                _safe(tag.get("access")),
                _safe(tag.get("datatype")),
                _safe(tag.get("description")),
                _safe(tag.get("memory_region")),
            ]
        ).lower()

    def _a2l_tag_matches_find_query(self, tag: dict, query: str) -> bool:
        if not query.strip():
            return False
        return query.lower() in self._a2l_tag_find_haystack(tag)

    def _handle_a2l_tag_find_next(self) -> None:
        """
        Summary:
            Find the next filtered A2L tag matching the tag-find query, then page and highlight it.

        Args:
            None (reads ``#a2l_tag_find_input`` and ``_a2l_filtered_tags``).

        Returns:
            None

        Data Flow:
            - Normalize query and reset cyclic cursor when the query string changes.
            - Scan forward from the prior match with wrap-around.
            - Snap the table, set alt hex span highlight, and refresh the alt panel.

        Dependencies:
            Uses:
                - ``_a2l_tag_matches_find_query``
                - ``_focus_a2l_tag_absolute_index``
                - ``_a2l_tag_byte_length_for_hex_highlight``
                - ``update_alt_hex_view``
                - ``set_status``
            Used by:
                - ``on_button_pressed`` for ``a2l_tag_find_next``
                - ``action_a2l_tag_find_next``
        """
        query = self.query_one("#a2l_tag_find_input", Input).value.strip()
        if not query:
            self.set_status("Tag find query is empty.")
            return
        tags = self._a2l_filtered_tags
        if not tags:
            self.set_status("No A2L tags to search.")
            return
        if query != self._a2l_tag_find_query:
            self._a2l_tag_find_query = query
            self._a2l_tag_find_last_index = -1
        n = len(tags)
        start = (self._a2l_tag_find_last_index + 1) % n
        for k in range(n):
            i = (start + k) % n
            if self._a2l_tag_matches_find_query(tags[i], query):
                self._a2l_tag_find_last_index = i
                self._focus_a2l_tag_absolute_index(i)
                addr = tags[i].get("address")
                if isinstance(addr, int):
                    span = self._a2l_tag_byte_length_for_hex_highlight(tags[i])
                    self._a2l_tag_hex_highlight = (addr, span)
                    self.update_alt_hex_view(addr)
                else:
                    self.update_alt_hex_view()
                name = str(tags[i].get("name") or "")
                self.set_status(f"Tag find: {name} (row {i + 1})")
                return
        self.set_status("Tag find: no match.")

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

    def _jump_to_validation_issue(self, item: ListItem) -> None:
        """Focus related hex/tag context for a selected validation issue row."""
        info = getattr(item, "data", None)
        if not isinstance(info, dict):
            return
        address = info.get("address")
        if isinstance(address, int) and self.current_file:
            self.update_hex_view(address)
            self.update_alt_hex_view(address)
            self.update_mac_hex_view(address)
            self.set_status(f"Issue at 0x{address:08X}: {info.get('code', 'validation')}")
            return
        symbol = str(info.get("symbol") or "").strip()
        if symbol and self._a2l_filtered_tags:
            for index, tag in enumerate(self._a2l_filtered_tags):
                if str(tag.get("name") or "").strip().lower() == symbol.lower():
                    if self._focus_a2l_tag_absolute_index(index):
                        self.action_view_alt()
                        self.set_status(f"Issue symbol focused: {symbol}")
                    return

    def _deduplicate_issues(self, issues: list[ValidationIssue]) -> list[ValidationIssue]:
        """Drop duplicate issues by stable identity tuple while preserving order."""
        deduped: list[ValidationIssue] = []
        seen: set[tuple[Any, ...]] = set()
        for issue in issues:
            key = (
                issue.code,
                issue.severity.value,
                issue.message,
                issue.artifact,
                issue.symbol,
                issue.address,
                issue.line_number,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(issue)
        return deduped

    def _filtered_validation_issues(self) -> list[ValidationIssue]:
        """Return cached validation issues filtered by active severity mode."""
        if self.validation_issue_filter_mode == "error":
            return [item for item in self._validation_issues if item.severity == ValidationSeverity.ERROR]
        if self.validation_issue_filter_mode == "warning":
            return [item for item in self._validation_issues if item.severity == ValidationSeverity.WARNING]
        return list(self._validation_issues)

    def _format_validation_issue_line(self, issue: ValidationIssue) -> str:
        symbol = issue.symbol or "-"
        addr = f"0x{issue.address:08X}" if isinstance(issue.address, int) else "-"
        line_no = str(issue.line_number) if isinstance(issue.line_number, int) else "-"
        return (
            f"[{issue.severity.value.upper()}] {issue.code} | {issue.artifact} | "
            f"sym={symbol} addr={addr} line={line_no} | {issue.message}"
        )

    def update_validation_issues_view(self) -> None:
        """Render the validation issue panel with active severity filter."""
        issue_list = self.query_one("#validation_issues_list", ListView)
        issue_list.clear()
        filtered = self._filtered_validation_issues()
        if not filtered:
            issue_list.append(ListItem(Label("No validation issues.")))
            return
        error_count = len([item for item in self._validation_issues if item.severity == ValidationSeverity.ERROR])
        warning_count = len([item for item in self._validation_issues if item.severity == ValidationSeverity.WARNING])
        info_count = len([item for item in self._validation_issues if item.severity == ValidationSeverity.INFO])
        issue_list.append(
            ListItem(
                Label(
                    " | ".join(
                        [
                            f"total={len(self._validation_issues)}",
                            f"errors={error_count}",
                            f"warnings={warning_count}",
                            f"info={info_count}",
                            f"filter={self.validation_issue_filter_mode}",
                        ]
                    )
                )
            )
        )
        for issue in filtered:
            label = Label(self._format_validation_issue_line(issue))
            label.add_class(css_class_for_severity(issue.severity))
            item = ListItem(label)
            item.data = {
                "code": issue.code,
                "symbol": issue.symbol,
                "address": issue.address,
                "line_number": issue.line_number,
            }
            issue_list.append(item)

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
        a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
        self.logger.info(
            "MAC parse summary: path=%s total_records=%d parse_ok=%d diagnostics=%d valid_addresses=%d a2l_path=%s",
            path,
            len(records),
            len([item for item in records if item.get("parse_ok")]),
            len(diagnostics),
            len(valid_addresses),
            a2l_path,
        )
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
            mac_path=path,
            mac_records=records,
            mac_diagnostics=diagnostics,
        )

    def _mac_address_in_ranges(self, address: int, ranges: list[tuple[int, int]]) -> bool:
        """Return whether an address belongs to any loaded image section."""
        for start, end in ranges:
            if start <= address < end:
                return True
        return False

    def _collect_mac_out_of_range_addresses(self, loaded: Optional[LoadedFile]) -> set[int]:
        """Return parsed MAC addresses that are outside loaded S19/HEX ranges."""
        if not loaded or loaded.file_type not in {"s19", "hex"}:
            return set()
        out_of_range: set[int] = set()
        for record in loaded.mac_records or []:
            address = record.get("address")
            if not (record.get("parse_ok") and isinstance(address, int)):
                continue
            if not self._mac_address_in_ranges(address, loaded.ranges):
                out_of_range.add(address)
        return out_of_range

    def _collect_mac_highlight_addresses(self, loaded: Optional[LoadedFile]) -> set[int]:
        """Return parsed MAC addresses for optional orange hex overlays."""
        if not loaded:
            return set()
        addresses: set[int] = set()
        for record in loaded.mac_records or []:
            address = record.get("address")
            if record.get("parse_ok") and isinstance(address, int):
                addresses.add(address)
        return addresses

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
            load_started = time.perf_counter()
            self.logger.info("Loading file: path=%s suffix=%s project=%s", path, suffix, self.current_project)
            if suffix in S19_EXTENSIONS:
                s19 = S19File(str(path))
                mem_map = build_mem_map_s19(s19)
                row_bases = build_row_bases(mem_map)
                ranges = s19._get_memory_ranges()
                range_validity = build_range_validity_s19(s19, ranges)
                errors = s19.get_errors()
                a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
                a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
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
                    mac_path=None,
                    mac_records=[],
                    mac_diagnostics=[],
                )
                self._log_loaded_file_summary(
                    file_type="s19",
                    path=path,
                    mem_map=mem_map,
                    ranges=ranges,
                    errors=errors,
                )
            elif suffix in HEX_EXTENSIONS:
                hex_file = IntelHexFile(str(path))
                mem_map = dict(hex_file.memory)
                row_bases = build_row_bases(mem_map)
                ranges = hex_file.get_ranges()
                range_validity = build_range_validity_hex(hex_file, ranges)
                errors = hex_file.get_errors()
                a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
                a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
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
                    mac_path=None,
                    mac_records=[],
                    mac_diagnostics=[],
                )
                self._log_loaded_file_summary(
                    file_type="hex",
                    path=path,
                    mem_map=mem_map,
                    ranges=ranges,
                    errors=errors,
                )
            elif suffix in MAC_EXTENSIONS:
                mac_loaded = self._load_mac_file(path, a2l_files)
                if self.current_file and self.current_file.file_type in {"s19", "hex"}:
                    loaded = LoadedFile(
                        path=self.current_file.path,
                        file_type=self.current_file.file_type,
                        mem_map=self.current_file.mem_map,
                        row_bases=self.current_file.row_bases,
                        ranges=self.current_file.ranges,
                        range_validity=self.current_file.range_validity,
                        errors=self.current_file.errors,
                        a2l_path=mac_loaded.a2l_path or self.current_file.a2l_path,
                        a2l_data=mac_loaded.a2l_data or self.current_file.a2l_data,
                        mac_path=path,
                        mac_records=mac_loaded.mac_records,
                        mac_diagnostics=mac_loaded.mac_diagnostics,
                    )
                    self._log_loaded_file_summary(
                        file_type=f"{loaded.file_type}+mac",
                        path=path,
                        mem_map=loaded.mem_map,
                        ranges=loaded.ranges,
                        errors=loaded.errors,
                    )
                else:
                    loaded = mac_loaded
                    self._log_loaded_file_summary(
                        file_type="mac",
                        path=path,
                        mem_map=loaded.mem_map,
                        ranges=loaded.ranges,
                        errors=loaded.errors,
                    )
            else:
                self.set_status(f"Unsupported file type: {suffix}")
                self.logger.warning("Unsupported file type in loader: %s", suffix)
                return
        except Exception as exc:
            self.set_status(f"Load failed: {exc}")
            self.logger.exception("Load failed for path=%s suffix=%s project=%s", path, suffix, self.current_project)
            return
        self.current_file = loaded
        self._mac_window_start = 0
        self._a2l_tag_hex_highlight = None
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
        total_elapsed = time.perf_counter() - load_started
        self.logger.info("Loaded file successfully: path=%s elapsed_seconds=%.3f", path, total_elapsed)

    def _load_a2l_data_with_cache(self, path: Optional[Path]) -> Optional[dict[str, Any]]:
        """
        Summary:
            Parse A2L once per unchanged file metadata and reuse cached payload for repeated loads.

        Args:
            path (Optional[Path]): A2L file path; when None, no parse is attempted.

        Returns:
            Optional[dict[str, Any]]: Parsed A2L payload from cache or fresh parse, or None for empty path.

        Data Flow:
            - Build cache key from resolved path string, mtime, and byte size.
            - Return cached payload when key matches previous parsed file.
            - Parse with ``parse_a2l_file`` on cache miss, then store key and payload.
            - Emit cache hit/miss logs for diagnostics.

        Dependencies:
            Uses:
                - ``parse_a2l_file``
                - ``Path.stat``
            Used by:
                - ``load_a2l_from_path``
                - ``load_selected_file``
                - ``_load_mac_file``
        """
        if not path:
            return None
        stat = path.stat()
        cache_key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
        if self._a2l_cache_key == cache_key and self._a2l_cache_data is not None:
            self.logger.info("A2L cache hit: path=%s size_bytes=%d", path, stat.st_size)
            return self._a2l_cache_data
        self.logger.info("A2L cache miss: path=%s size_bytes=%d", path, stat.st_size)
        parsed = parse_a2l_file(path)
        self._a2l_cache_key = cache_key
        self._a2l_cache_data = parsed
        return parsed

    def _log_a2l_parse_summary(self, path: Path, a2l_data: Optional[dict[str, Any]], elapsed_seconds: float) -> None:
        """
        Summary:
            Log a normalized A2L parse result summary and emit warnings for slow or error-heavy loads.

        Args:
            path (Path): Parsed A2L path.
            a2l_data (Optional[dict[str, Any]]): Parse payload from ``parse_a2l_file``.
            elapsed_seconds (float): Total parse stage duration in seconds.

        Returns:
            None

        Data Flow:
            - Derive section, tag, and parse error counts from payload.
            - Emit INFO summary with elapsed time and payload dimensions.
            - Emit WARNING when elapsed time exceeds configured threshold.
            - Emit WARNING with sample parse errors when parser reports structural issues.

        Dependencies:
            Uses:
                - ``logger.info`` / ``logger.warning``
            Used by:
                - ``load_a2l_from_path``
        """
        payload = a2l_data or {}
        sections = payload.get("sections", [])
        tags = payload.get("tags", [])
        errors = payload.get("errors", [])
        self.logger.info(
            "A2L parse summary: path=%s elapsed_seconds=%.3f sections=%d tags=%d errors=%d",
            path,
            elapsed_seconds,
            len(sections),
            len(tags),
            len(errors),
        )
        if elapsed_seconds > self.slow_parse_warn_seconds:
            self.logger.warning(
                "A2L parse exceeded threshold: path=%s elapsed_seconds=%.3f threshold_seconds=%.3f",
                path,
                elapsed_seconds,
                self.slow_parse_warn_seconds,
            )
        if errors:
            sample = "; ".join(str(item) for item in errors[:3])
            self.logger.warning("A2L parse reported structural errors: path=%s sample=%s", path, sample)

    def _log_loaded_file_summary(
        self,
        file_type: str,
        path: Path,
        mem_map: dict[int, int],
        ranges: list[tuple[int, int]],
        errors: list[dict[str, Any]],
    ) -> None:
        """
        Summary:
            Emit standardized post-parse diagnostics for S19, HEX, and MAC load branches.

        Args:
            file_type (str): Loader branch identifier (``s19``, ``hex``, ``mac``).
            path (Path): Parsed file path.
            mem_map (dict[int, int]): Materialized memory map keyed by absolute address.
            ranges (list[tuple[int, int]]): Contiguous ranges as ``(start, end_exclusive)``.
            errors (list[dict[str, Any]]): Parser diagnostics in normalized dict form.

        Returns:
            None

        Data Flow:
            - Compute aggregate metrics (address count, total bytes, range count, error count).
            - Emit INFO summary for searchable diagnostics.
            - Emit WARNING with compact samples when parser errors exist.

        Dependencies:
            Uses:
                - ``logger.info`` / ``logger.warning``
            Used by:
                - ``load_selected_file``
        """
        range_bytes = sum(max(0, end - start) for start, end in ranges)
        self.logger.info(
            "Load summary: file_type=%s path=%s addresses=%d range_count=%d range_bytes=%d errors=%d",
            file_type,
            path,
            len(mem_map),
            len(ranges),
            range_bytes,
            len(errors),
        )
        if errors:
            sample = []
            for item in errors[:3]:
                segment = item.get("segment")
                line_number = item.get("line_number")
                message = item.get("error") or item.get("message")
                sample.append(f"line={line_number} segment={segment} error={message}")
            self.logger.warning("Load diagnostics: file_type=%s path=%s sample=%s", file_type, path, " | ".join(sample))

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
            severity = ValidationSeverity.OK if is_valid else ValidationSeverity.ERROR
            label.add_class(css_class_for_severity(severity))
            item = ListItem(label)
            item.data = (start, end)
            sections.append(item)
        out_of_range = sorted(self._collect_mac_out_of_range_addresses(self.current_file))
        for address in out_of_range:
            label = Label(f"MAC out-of-range @ 0x{address:08X}")
            label.add_class("mac_out_of_range")
            item = ListItem(label)
            item.data = (address, address + 1)
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
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
                mac_highlights,
            )
        )
        if focus_address is not None:
            self.logger.info("Hex view focused at 0x%08X", focus_address)

    def update_alt_hex_view(self, focus_address: Optional[int] = None) -> None:
        """
        Summary:
            Render the alternate hex panel with optional focus and a highlight span.

        Args:
            focus_address (Optional[int]): Center the view on this address when set.

        Returns:
            None

        Data Flow:
            - Prefer ``_a2l_tag_hex_highlight`` (address, length) when present.
            - Otherwise use ASCII alt-search hit span from ``last_search_*``.
            - Render via ``render_hex_view_text`` into ``#alt_hex_view``.

        Dependencies:
            Uses:
                - ``render_hex_view_text``
            Used by:
                - ``load_selected_file``
                - ``_jump_to_tag``
                - ``_handle_a2l_tag_find_next``
                - ``_handle_search_alt`` / ``_handle_goto_alt``
        """
        alt_hex_view = self.query_one("#alt_hex_view", Static)
        if not self.current_file:
            alt_hex_view.update("No file loaded.")
            return
        highlight = None
        if self._a2l_tag_hex_highlight is not None:
            highlight = self._a2l_tag_hex_highlight
        elif self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        alt_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
                mac_highlights,
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
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        mac_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                self.current_file.row_bases,
                highlight,
                mac_highlights,
            )
        )

    def update_mac_view(self) -> None:
        """
        Summary:
            Populate the MAC viewer list with a paged window of ``.mac`` rows, A2L cross-check
            columns, validation coloring, and aggregate counts.

        Args:
            (none; reads ``current_file``, ``current_a2l_data``, and widget ``#mac_records_list``.)

        Returns:
            None

        Data Flow:
            - Build full-row metadata for every MAC record (global counts).
            - Slice one page of rows using ``mac_records_page_size`` and ``_mac_window_start``.
            - Color rows via ``_mac_record_ui_state``: green when A2L name+address match, red on parse/out-of-image/address mismatch, default when not verifiable against A2L.

        Dependencies:
            Uses:
                - ``_build_a2l_name_index``
                - ``_mac_record_ui_state``
                - ``_mac_clamp_page_start`` / ``_get_window_bounds``
                - ``query_one`` / ``ListView`` / ``Label`` / ``ListItem``
            Used by:
                - ``load_selected_file`` post-load refresh
                - ``update_a2l_view`` when A2L data changes
                - MAC paging actions
        """
        mac_list = self.query_one("#mac_records_list", ListView)
        mac_list.clear()
        if not self.current_file or not self.current_file.mac_records:
            mac_list.append(ListItem(Label("No MAC loaded.")))
            self._validation_report = None
            self._validation_issues = []
            self.update_validation_issues_view()
            return
        records = self.current_file.mac_records or []
        if not records:
            mac_list.append(ListItem(Label("No MAC records parsed.")))
            self._validation_report = None
            self._validation_issues = []
            self.update_validation_issues_view()
            return

        has_a2l = bool(self.current_a2l_data)
        a2l_name_index = _build_a2l_name_index(self.current_a2l_data)
        rows: list[tuple] = []
        row_meta: list[dict[str, Any]] = []
        total_verified = 0
        total_invalid = 0
        total_neutral = 0
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
                in_memory = self._mac_address_in_ranges(address, self.current_file.ranges)

            in_mem_text = "n/a"
            if memory_checked:
                in_mem_text = "yes" if in_memory else "no"
                if not in_memory:
                    total_out_of_mem += 1

            status, severity_text = _mac_record_ui_state(
                record, a2l_name_index, has_a2l, memory_checked, in_memory
            )
            severity = ValidationSeverity(severity_text)
            if severity == ValidationSeverity.OK:
                total_verified += 1
            elif severity == ValidationSeverity.ERROR:
                total_invalid += 1
            else:
                total_neutral += 1

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
                    "severity": severity,
                    "address": address if isinstance(address, int) else None,
                }
            )

        total = len(rows)
        self._mac_window_start = self._mac_clamp_page_start(total)
        page_size = max(1, self.mac_records_page_size)
        start, end = self._get_window_bounds(total, self._mac_window_start, page_size)
        self._mac_window_start = start
        visible_rows = rows[start:end]
        visible_meta = row_meta[start:end]

        name_width = min(48, max(len("Tag"), *(len(row[0]) for row in rows)))
        addr_width = max(len("Address"), *(len(row[1]) for row in rows))
        in_a2l_width = max(len("InA2L"), *(len(row[2]) for row in rows))
        in_mem_width = max(len("InMem"), *(len(row[3]) for row in rows))
        status_width = max(len("Status"), *(len(row[4]) for row in rows))
        line_width = max(len("SourceLine"), *(len(row[5]) for row in rows))
        parse_width = min(36, max(len("ParseErr"), *(len(row[6]) for row in rows)))
        match_width = min(36, max(len("A2LMatch"), *(len(row[7]) for row in rows)))

        page_num = start // page_size + 1
        total_pages = max(1, (total + page_size - 1) // page_size)
        page_line = (
            f"Page {page_num}/{total_pages} | rows {start + 1}-{end} / {total} "
            f"(page size {page_size}; comma/period for MAC page)"
        )
        mac_list.append(ListItem(Label(page_line)))

        header = (
            f"{'Tag'.ljust(name_width)} | {'Address'.ljust(addr_width)} | "
            f"{'InA2L'.ljust(in_a2l_width)} | {'InMem'.ljust(in_mem_width)} | "
            f"{'Status'.ljust(status_width)} | {'SourceLine'.ljust(line_width)} | "
            f"{'ParseErr'.ljust(parse_width)} | {'A2LMatch'.ljust(match_width)}"
        )
        mac_list.append(ListItem(Label(header)))

        for index, row in enumerate(visible_rows):
            line = (
                f"{row[0][:name_width].ljust(name_width)} | {row[1].ljust(addr_width)} | "
                f"{row[2].ljust(in_a2l_width)} | {row[3].ljust(in_mem_width)} | "
                f"{row[4].ljust(status_width)} | {row[5].ljust(line_width)} | "
                f"{row[6][:parse_width].ljust(parse_width)} | {row[7][:match_width].ljust(match_width)}"
            )
            label = Label(line)
            label.add_class(css_class_for_severity(visible_meta[index]["severity"]))
            item = ListItem(label)
            item.data = {"address": visible_meta[index]["address"]}
            mac_list.append(item)

        summary = (
            f"Total={total}  Verified={total_verified}  Invalid={total_invalid}  Neutral={total_neutral}  "
            f"NameInA2L={total_in_a2l}  OutOfMem={total_out_of_mem}  ParseErrs={total_parse_errors}"
        )
        mac_list.append(ListItem(Label(summary)))
        if self.current_file.file_type in {"s19", "hex"}:
            report = validate_artifact_consistency(
                mac_records=records,
                a2l_tags=self._a2l_enriched_tags or (self.current_a2l_data or {}).get("tags", []),
                a2l_data=self.current_a2l_data,
                s19_ranges=self.current_file.ranges,
                overlapped_addresses=set(),
            )
            extra_a2l_issues = (
                validate_a2l_internal_issues(
                    self.current_a2l_data or {"sections": [], "errors": [], "tags": []},
                    tag_checks=self._a2l_enriched_tags,
                )
                if self.current_a2l_data
                else []
            )
            report.issues = self._deduplicate_issues(report.issues + extra_a2l_issues)
            self._validation_report = report
            self._validation_issues = report.issues
            coverage_line = (
                f"Coverage MAC->S19={report.coverage.mac_in_s19_pct():.1f}%  "
                f"A2L->S19={report.coverage.a2l_in_s19_pct():.1f}%  "
                f"A2L<->MAC={report.coverage.a2l_mac_match_pct():.1f}%"
            )
            coverage_label = Label(coverage_line)
            coverage_label.add_class("sev-info")
            mac_list.append(ListItem(coverage_label))
        else:
            self._validation_report = None
            self._validation_issues = []
        self.update_validation_issues_view()

    def _compute_a2l_enriched_tags(self) -> list[dict[str, Any]]:
        """
        Summary:
            Build and cache validated A2L tag payload used by summary, filters, and buffered list rendering.

        Args:
            None

        Returns:
            list[dict[str, Any]]: Enriched A2L tags with schema/memory validation fields.

        Data Flow:
            - Derive cache key from current A2L payload identity and memory map size.
            - Reuse previous enriched list when key is unchanged.
            - Run ``validate_a2l_tags`` and merge results onto source tags on cache miss.

        Dependencies:
            Uses:
                - ``validate_a2l_tags``
            Used by:
                - ``update_a2l_view``
                - A2L filter debounce render path
        """
        if not self.current_a2l_data:
            self._a2l_enriched_tags = []
            self._a2l_enriched_key = None
            return []
        mem_map = self.current_file.mem_map if self.current_file else None
        mem_size = len(mem_map) if mem_map is not None else -1
        key = (id(self.current_a2l_data), mem_size)
        if self._a2l_enriched_key == key:
            return self._a2l_enriched_tags
        source_tags = self.current_a2l_data.get("tags", [])
        tag_checks = validate_a2l_tags(source_tags, mem_map)
        check_map = {(t.get("section"), t.get("name")): t for t in tag_checks}
        enriched: list[dict[str, Any]] = []
        for tag in source_tags:
            lookup = (tag.get("section"), tag.get("name"))
            enriched.append({**tag, **check_map.get(lookup, {})})
        self._a2l_enriched_tags = enriched
        self._a2l_enriched_key = key
        self._a2l_summary_lines = render_a2l_view(self.current_a2l_data, tag_checks, max_tag_lines=500).splitlines()
        self._a2l_summary_start = 0
        return enriched

    def _update_a2l_summary_buffer(self) -> None:
        """
        Summary:
            Render a buffered slice of A2L summary lines into the summary panel.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Clamp summary window start/end indices.
            - Build header describing visible slice.
            - Push visible lines only into ``#a2l_view`` widget.

        Dependencies:
            Uses:
                - ``_get_window_bounds``
            Used by:
                - ``update_a2l_view``
        """
        a2l_view = self.query_one("#a2l_view", Static)
        if not self._a2l_summary_lines:
            a2l_view.update("No A2L loaded.")
            return
        total = len(self._a2l_summary_lines)
        start, end = self._get_window_bounds(total, self._a2l_summary_start, self.a2l_summary_window_size)
        self._a2l_summary_start = start
        visible = self._a2l_summary_lines[start:end]
        header = f"A2L summary lines {start + 1}-{end} / {total}"
        a2l_view.update("\n".join([header, "-" * len(header), *visible]))

    def _refresh_a2l_filtered_tags(self, preserve_anchor: bool) -> None:
        """
        Summary:
            Rebuild filtered A2L tag source list and render a buffered window.

        Args:
            preserve_anchor (bool): Keep current buffered start when possible; otherwise reset to top.

        Returns:
            None

        Data Flow:
            - Apply active filter mode/text to cached enriched tags.
            - Optionally reset buffered start index on filter model changes.
            - Render only current buffered window to list view.

        Dependencies:
            Uses:
                - ``_filter_a2l_tags``
                - ``update_a2l_tags_view``
            Used by:
                - ``update_a2l_view``
                - filter and debounce handlers
        """
        self._a2l_filtered_tags = self._filter_a2l_tags(self._a2l_enriched_tags)
        if not preserve_anchor:
            self._a2l_window_start = 0
        else:
            self._a2l_window_start = self._a2l_clamp_page_start(len(self._a2l_filtered_tags))
        self.update_a2l_tags_view(self._a2l_filtered_tags)

    def update_a2l_view(self) -> None:
        """Render buffered A2L summary and tags views."""
        if not self.current_a2l_data:
            self._a2l_enriched_tags = []
            self._a2l_filtered_tags = []
            self._a2l_summary_lines = []
            self._a2l_window_start = 0
            self._a2l_tag_hex_highlight = None
            self._a2l_tag_find_query = ""
            self._a2l_tag_find_last_index = -1
            self._update_a2l_summary_buffer()
            self.update_a2l_tags_view([])
            self.update_mac_view()
            if not self.current_file:
                self._validation_report = None
                self._validation_issues = []
                self.update_validation_issues_view()
            return
        self._compute_a2l_enriched_tags()
        filter_input = self.query_one("#a2l_tags_filter_input", Input)
        self.a2l_tags_filter_text = filter_input.value.strip()
        self._refresh_a2l_filtered_tags(preserve_anchor=False)
        self._update_a2l_summary_buffer()
        self.update_mac_view()

    def update_a2l_tags_view(self, tags: list[dict]) -> None:
        """
        Summary:
            Render one page of A2L tag rows with fixed page size and a page-oriented summary line.

        Args:
            tags (list[dict]): Filtered enriched tags to display (may be empty).

        Returns:
            None

        Data Flow:
            - Clamp ``_a2l_window_start`` to a legal page boundary for ``a2l_tags_page_size``.
            - Slice ``tags`` for the current page only and build fixed-width table rows.
            - Attach ``absolute_index`` and full ``tag`` dict on each data ``ListItem``.

        Dependencies:
            Uses:
                - ``_a2l_clamp_page_start``
                - ``_get_window_bounds``
                - ``_a2l_tag_row_invalid``
            Used by:
                - ``_refresh_a2l_filtered_tags``
                - ``update_a2l_view``
                - A2L tag paging and find actions
        """
        a2l_tags_list = self.query_one("#a2l_tags_list", ListView)
        a2l_tags_list.clear()
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H3",
            location="s19_app/tui/app.py:update_a2l_tags_view",
            message="Entered update_a2l_tags_view",
            data={"incoming_tag_count": len(tags)},
        )
        # endregion
        if not tags:
            self._a2l_window_start = 0
            a2l_tags_list.append(ListItem(Label("No A2L tags.")))
            return
        total_tags = len(tags)
        self._a2l_window_start = self._a2l_clamp_page_start(total_tags)
        page_size = max(1, self.a2l_tags_page_size)
        start, end = self._get_window_bounds(total_tags, self._a2l_window_start, page_size)
        self._a2l_window_start = start
        visible_tags = tags[start:end]
        rows: list[tuple] = []
        row_tags: list[dict] = []
        for tag in visible_tags:
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
        page_num = start // page_size + 1
        total_pages = max(1, (total_tags + page_size - 1) // page_size)
        summary = (
            f"Page {page_num}/{total_pages} | tags {start + 1}-{end} / {total_tags} "
            f"(page size {page_size}; +/- or Ctrl+[ / Ctrl+] to change page)"
        )
        a2l_tags_list.append(ListItem(Label(summary)))
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
            label.add_class(css_class_for_severity(_a2l_tag_row_severity(row_tags[i])))
            item = ListItem(label)
            item.data = {"address": row[1], "name": row[0], "tag": row_tags[i]}
            item.data["absolute_index"] = start + i
            if isinstance(row[1], str) and row[1].startswith("0x"):
                try:
                    item.data["address"] = int(row[1], 16)
                except ValueError:
                    pass
            a2l_tags_list.append(item)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H3",
            location="s19_app/tui/app.py:update_a2l_tags_view",
            message="Finished update_a2l_tags_view",
            data={"rendered_tag_rows": len(rows), "total_rows": total_tags, "start": start, "end": end},
        )
        # endregion

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
        self._refresh_a2l_filtered_tags(preserve_anchor=False)

    def _schedule_a2l_filter_refresh(self) -> None:
        """
        Summary:
            Debounce rapid filter-input events and refresh only buffered A2L tags window.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Increment debounce token for each new keystroke.
            - Schedule short delayed callback.
            - Refresh filtered buffered rows only if token matches latest request.

        Dependencies:
            Uses:
                - ``set_timer``
                - ``_refresh_a2l_filtered_tags``
            Used by:
                - ``on_input_changed`` for A2L filter input
        """
        self._a2l_filter_debounce_token += 1
        expected_token = self._a2l_filter_debounce_token

        def _apply_filter() -> None:
            if expected_token != self._a2l_filter_debounce_token:
                return
            self._refresh_a2l_filtered_tags(preserve_anchor=False)

        self.set_timer(0.15, _apply_filter)

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
            self._refresh_a2l_filtered_tags(preserve_anchor=False)
        elif event.button.id == "a2l_filter_invalid":
            self.a2l_tags_filter_mode = "invalid"
            self._refresh_a2l_filtered_tags(preserve_anchor=False)
        elif event.button.id == "a2l_filter_inmem":
            self.a2l_tags_filter_mode = "inmem"
            self._refresh_a2l_filtered_tags(preserve_anchor=False)
        elif event.button.id == "a2l_filter_field":
            self._toggle_a2l_filter_menu()
        elif event.button.id == "a2l_tag_find_next":
            self._handle_a2l_tag_find_next()
        elif event.button.id == "issues_filter_all":
            self.validation_issue_filter_mode = "all"
            self.update_validation_issues_view()
        elif event.button.id == "issues_filter_error":
            self.validation_issue_filter_mode = "error"
            self.update_validation_issues_view()
        elif event.button.id == "issues_filter_warning":
            self.validation_issue_filter_mode = "warning"
            self.update_validation_issues_view()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "a2l_tags_filter_input":
            self.a2l_tags_filter_text = event.value.strip()
            self._schedule_a2l_filter_refresh()
        elif event.input.id == "a2l_tag_find_input":
            self._a2l_tag_find_last_index = -1

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
        self._a2l_tag_hex_highlight = None
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
        self._a2l_tag_hex_highlight = None
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
