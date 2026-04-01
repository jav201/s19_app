"""
Textual TUI for S19/HEX inspection with optional A2L support.

High-level responsibilities:
- Manage a workarea for transient loads and saved projects.
- Load and parse S19/HEX data, build ranges, and render hex view.
- Load and minimally parse A2L files and show a readable summary.
- Enforce project rules (one data file + one A2L per project).
- Provide actions/bindings for common workflows and export helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import shutil

from textual.app import App, ComposeResult
from rich.text import Text
from textual.containers import Container, ScrollableContainer
from textual.screen import ModalScreen
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
from textual.reactive import reactive

from .core import S19File
from .hexfile import IntelHexFile


WORKAREA_DIRNAME = ".s19tool"
WORKAREA_SUBDIR = "workarea"
WORKAREA_TEMP = "temp"
LOGS_SUBDIR = "logs"
LOG_FILENAME = "s19tui.log"
MAX_HEX_BYTES = 65536
HEX_WIDTH = 16
FOCUS_CONTEXT_ROWS = 64
MAX_HEX_ROWS = 512
SEARCH_ENCODING = "ascii"
S19_EXTENSIONS = {".s19", ".srec"}
HEX_EXTENSIONS = {".hex", ".ihex"}
A2L_EXTENSIONS = {".a2l"}
SUPPORTED_EXTENSIONS = S19_EXTENSIONS | HEX_EXTENSIONS
PROJECT_DATA_EXTENSIONS = SUPPORTED_EXTENSIONS


@dataclass
class LoadedFile:
    path: Path
    file_type: str
    mem_map: Dict[int, int]
    row_bases: List[int]
    ranges: List[Tuple[int, int]]
    range_validity: List[bool]
    errors: List[dict]
    a2l_path: Optional[Path]
    a2l_data: Optional[dict]


def ensure_workarea(base_dir: Path) -> Path:
    """Ensure workarea structure exists and return the workarea path."""
    workarea_root = base_dir / WORKAREA_DIRNAME
    workarea = workarea_root / WORKAREA_SUBDIR
    workarea.mkdir(parents=True, exist_ok=True)
    (workarea / WORKAREA_TEMP).mkdir(parents=True, exist_ok=True)
    (workarea_root / LOGS_SUBDIR).mkdir(parents=True, exist_ok=True)
    return workarea


def setup_logging(base_dir: Path) -> logging.Logger:
    """Configure a rotating file logger under .s19tool/logs."""
    logs_dir = base_dir / WORKAREA_DIRNAME / LOGS_SUBDIR 
    logs_dir.mkdir(parents=True, exist_ok=True) # Ensure the logs directory exists
    log_path = logs_dir / LOG_FILENAME

    logger = logging.getLogger("s19tui") # Get the logger for the s19tui application
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler_exists = False
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler):
            if getattr(handler, "baseFilename", None) == str(log_path):
                handler_exists = True
                break

    if not handler_exists:
        handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024, # 5 MB
            backupCount=1, # Keep only the latest log file
            encoding="utf-8",
        )
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s", 
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        try:
            log_path.touch(exist_ok=True)
        except Exception:
            pass
    return logger


def copy_into_workarea(source: Path, destination: Path) -> Path:
    """Copy a file into a target directory, avoiding name collisions."""
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / source.name
    if target.exists():
        stem = source.stem
        suffix = source.suffix
        counter = 1
        while True:
            candidate = destination / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1
    shutil.copy2(source, target)
    return target


def sanitize_project_name(name: str) -> Optional[str]:
    """Return a filesystem-safe project name or None if empty after cleaning."""
    cleaned = "".join(ch for ch in name.strip() if ch.isalnum() or ch in {"-", "_"})
    return cleaned if cleaned else None


def validate_project_files(project_dir: Path) -> tuple[list[Path], list[Path], Optional[str]]:
    """Return (data_files, a2l_files, error_message) enforcing project rules."""
    data_files = []
    a2l_files = []
    for item in project_dir.iterdir():
        if not item.is_file():
            continue
        suffix = item.suffix.lower()
        if suffix in PROJECT_DATA_EXTENSIONS:
            data_files.append(item)
        elif suffix in A2L_EXTENSIONS:
            a2l_files.append(item)
    if len(data_files) > 1:
        return data_files, a2l_files, "Project already has more than one S19/HEX file."
    if len(a2l_files) > 1:
        return data_files, a2l_files, "Project already has more than one A2L file."
    return data_files, a2l_files, None


def parse_a2l_file(path: Path) -> dict:
    """Minimal A2L parser that captures /begin.../end blocks and errors."""
    sections: list[dict] = []
    stack: list[dict] = []
    errors: list[str] = []
    tags: list[dict] = []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw in enumerate(handle, 1):
                line = raw.rstrip()
                stripped = line.strip()
                if stripped.lower().startswith("/begin"):
                    parts = stripped.split(maxsplit=2)
                    section_name = parts[1] if len(parts) > 1 else "UNKNOWN"
                    section_meta = parts[2] if len(parts) > 2 else ""
                    entry = {
                        "name": section_name,
                        "meta": section_meta,
                        "start_line": line_number,
                        "lines": [],
                        "children": [],
                    }
                    if stack:
                        stack[-1]["children"].append(entry)
                    else:
                        sections.append(entry)
                    stack.append(entry)
                    continue
                if stripped.lower().startswith("/end"):
                    if stack:
                        stack[-1]["end_line"] = line_number
                        stack.pop()
                    else:
                        errors.append(f"Line {line_number}: /end without /begin")
                    continue
                if stack:
                    stack[-1]["lines"].append(line)
    except FileNotFoundError:
        errors.append("File not found.")

    if stack:
        errors.append("Unclosed /begin sections detected.")

    tags = extract_a2l_tags(sections)
    return {
        "path": str(path),
        "sections": sections,
        "errors": errors,
        "tags": tags,
    }


def extract_a2l_tags(sections: list[dict]) -> list[dict]:
    """Extract tag name, address, and length from known A2L sections."""
    tags: list[dict] = []
    target_sections = {"CHARACTERISTIC", "MEASUREMENT"}

    def walk(section_list: list[dict]) -> None:
        for section in section_list:
            name = section.get("name", "")
            meta = section.get("meta", "")
            lines = section.get("lines", [])
            if name in target_sections:
                tag = {
                    "section": name,
                    "name": meta.split()[0] if meta else "UNKNOWN",
                    "address": None,
                    "length": None,
                }
                for line in lines:
                    stripped = line.strip()
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[0] == "ECU_ADDRESS":
                        try:
                            tag["address"] = int(parts[1], 0)
                        except ValueError:
                            tag["address"] = None
                    if len(parts) >= 2 and parts[0] in {"DATA_SIZE", "LENGTH"}:
                        try:
                            tag["length"] = int(parts[1], 0)
                        except ValueError:
                            tag["length"] = None
                tags.append(tag)
            if section.get("children"):
                walk(section["children"])

    walk(sections)
    return tags


def validate_a2l_tags(tags: list[dict], mem_map: Dict[int, int]) -> list[dict]:
    """Validate tags against loaded memory map (address + length)."""
    results: list[dict] = []
    for tag in tags:
        address = tag.get("address")
        length = tag.get("length")
        if address is None or length is None:
            results.append({**tag, "valid": False, "reason": "missing address/length"})
            continue
        missing = []
        for offset in range(length):
            addr = address + offset
            if addr not in mem_map:
                missing.append(addr)
                break
        if missing:
            results.append({**tag, "valid": False, "reason": "address range missing"})
        else:
            results.append({**tag, "valid": True, "reason": ""})
    return results


def render_a2l_view(a2l_data: Optional[dict], tag_checks: Optional[list[dict]] = None) -> str:
    """Render a concise, human-readable A2L summary or errors."""
    if not a2l_data:
        return "No A2L loaded."
    if a2l_data.get("errors"):
        errors = "\n".join(f"- {err}" for err in a2l_data["errors"])
        return f"A2L parse errors:\n{errors}"
    sections = a2l_data.get("sections", [])
    tags = a2l_data.get("tags", [])
    if not sections:
        return "No A2L sections found."
    lines = ["A2L Sections:"]
    for section in sections:
        name = section.get("name", "UNKNOWN")
        meta = section.get("meta", "")
        start = section.get("start_line")
        end = section.get("end_line")
        label = f"{name} {meta}".strip()
        lines.append(f"- {label} (lines {start}-{end})")
    if tags:
        lines.append("")
        lines.append("A2L Tags:")
        for tag in tags[:200]:
            addr = tag.get("address")
            length = tag.get("length")
            addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
            len_text = str(length) if isinstance(length, int) else "n/a"
            status = ""
            if tag_checks:
                match = next((item for item in tag_checks if item.get("name") == tag.get("name") and item.get("section") == tag.get("section")), None)
                if match:
                    status = "OK" if match.get("valid") else f"ERR ({match.get('reason')})"
            lines.append(f"- {tag.get('section')} {tag.get('name')}: {addr_text} len={len_text} {status}".strip())
    return "\n".join(lines)


def find_repo_root(start: Path) -> Optional[Path]:
    current = start.resolve()
    for _ in range(6):
        if (current / "pyproject.toml").exists() or (current / "project.toml").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def resolve_input_path(raw_path: Path, base_dir: Path) -> Optional[Path]:
    candidate = Path(str(raw_path).strip().strip('"')).expanduser()
    if candidate.exists():
        return candidate
    if not candidate.is_absolute():
        base_candidate = (base_dir / candidate).resolve()
        if base_candidate.exists():
            return base_candidate
        repo_root = find_repo_root(base_dir)
        if repo_root:
            repo_candidate = (repo_root / candidate).resolve()
            if repo_candidate.exists():
                return repo_candidate
    return None


def build_mem_map_s19(s19: S19File) -> Dict[int, int]:
    """Build an address->byte map from S19 data records."""
    mem_map: Dict[int, int] = {}
    for record in s19.records:
        for offset, value in enumerate(record.data):
            mem_map[record.address + offset] = value
    return mem_map


def build_range_validity_s19(s19: S19File, ranges: List[Tuple[int, int]]) -> List[bool]:
    """Mark each address range as valid/invalid based on record validity."""
    address_valid: Dict[int, bool] = {}
    for record in s19.records:
        for offset in range(len(record.data)):
            addr = record.address + offset
            current = address_valid.get(addr, True)
            address_valid[addr] = current and record.valid

    validity = []
    for start, end in ranges:
        is_valid = True
        for addr in range(start, end):
            if addr in address_valid and not address_valid[addr]:
                is_valid = False
                break
        validity.append(is_valid)
    return validity


def build_range_validity_hex(hex_file: IntelHexFile, ranges: List[Tuple[int, int]]) -> List[bool]:
    """Mark all HEX ranges invalid if any HEX parsing errors exist."""
    has_errors = len(hex_file.get_errors()) > 0
    return [not has_errors for _ in ranges]


def build_row_bases(mem_map: Dict[int, int]) -> List[int]:
    """Precompute row base addresses for faster hex rendering."""
    if not mem_map:
        return []
    addresses = sorted(mem_map.keys())
    return sorted({addr - (addr % HEX_WIDTH) for addr in addresses})


def find_string_in_mem(
    mem_map: Dict[int, int],
    query: str,
    start_address: Optional[int] = None,
) -> Optional[int]:
    """Return the first address where the query string appears from a start."""
    if not query:
        return None
    try:
        needle = query.encode(SEARCH_ENCODING)
    except UnicodeEncodeError:
        return None
    needle = needle.lower()
    addresses = sorted(mem_map.keys())
    if not addresses:
        return None

    start = 0
    if start_address is not None:
        for i, addr in enumerate(addresses):
            if addr >= start_address:
                start = i
                break
        else:
            return None

    idx_base = start
    while idx_base < len(addresses):
        run_start = idx_base
        run_end = run_start + 1
        while run_end < len(addresses) and addresses[run_end] == addresses[run_end - 1] + 1:
            run_end += 1
        run_addrs = addresses[run_start:run_end]
        run_bytes = bytes(mem_map[addr] for addr in run_addrs)
        idx = run_bytes.lower().find(needle)
        if idx != -1:
            return run_addrs[0] + idx
        idx_base = run_end
    return None


def _collect_hex_rows(
    mem_map: Dict[int, int],
    focus_address: Optional[int] = None,
    row_bases: Optional[List[int]] = None,
) -> tuple[List[str], List[Tuple[int, List[Optional[int]]]]]:
    bases = row_bases or build_row_bases(mem_map)
    if not bases:
        return ["No data available."], []

    lines: List[str] = []
    rows: List[Tuple[int, List[Optional[int]]]] = []

    start_index = 0
    if focus_address is not None:
        focus_base = focus_address - (focus_address % HEX_WIDTH)
        if focus_base in bases:
            focus_index = bases.index(focus_base)
            start_index = max(0, focus_index - FOCUS_CONTEXT_ROWS)
        else:
            lines.append(f"... address 0x{focus_address:08X} not present ...")

    if start_index > 0:
        lines.append(f"... showing from 0x{bases[start_index]:08X} (context preserved) ...")

    end_index = min(len(bases), start_index + MAX_HEX_ROWS)
    if end_index < len(bases):
        lines.append(f"... window limited to {MAX_HEX_ROWS} rows ...")

    bytes_rendered = 0
    for row_addr in bases[start_index:end_index]:
        row_bytes: List[Optional[int]] = []
        for offset in range(HEX_WIDTH):
            addr = row_addr + offset
            value = mem_map.get(addr)
            if value is not None:
                bytes_rendered += 1
            row_bytes.append(value)
        rows.append((row_addr, row_bytes))
        if bytes_rendered >= MAX_HEX_BYTES:
            lines.append(f"... output truncated at {MAX_HEX_BYTES} bytes ...")
            break

    return lines, rows


def render_hex_view(
    mem_map: Dict[int, int],
    focus_address: Optional[int] = None,
    row_bases: Optional[List[int]] = None,
) -> str:
    """Render a windowed hex+ASCII view for responsive UI."""
    header_lines, rows = _collect_hex_rows(mem_map, focus_address, row_bases)
    if rows == [] and header_lines:
        return "\n".join(header_lines)

    lines = header_lines[:]
    for row_addr, row_bytes in rows:
        hex_part = " ".join(f"{b:02X}" if b is not None else "  " for b in row_bytes)
        ascii_part = "".join(chr(b) if b is not None and 32 <= b <= 126 else "." for b in row_bytes)
        lines.append(f"0x{row_addr:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def render_hex_view_text(
    mem_map: Dict[int, int],
    focus_address: Optional[int],
    row_bases: Optional[List[int]],
    highlight: Optional[Tuple[int, int]],
) -> Text:
    """Render hex view with optional highlighted match range."""
    header_lines, rows = _collect_hex_rows(mem_map, focus_address, row_bases)
    text = Text()
    for line in header_lines:
        text.append(line + "\n")
    if not rows:
        return text

    highlight_start = highlight[0] if highlight else None
    highlight_end = highlight_start + highlight[1] if highlight else None
    highlight_style = "bold yellow"

    for row_addr, row_bytes in rows:
        text.append(f"0x{row_addr:08X}  ")
        for offset, value in enumerate(row_bytes):
            addr = row_addr + offset
            style = highlight_style if highlight_start is not None and highlight_start <= addr < highlight_end else None
            if value is None:
                text.append("   ")
            else:
                text.append(f"{value:02X} ", style=style)
        text.append(" |")
        for offset, value in enumerate(row_bytes):
            addr = row_addr + offset
            style = highlight_style if highlight_start is not None and highlight_start <= addr < highlight_end else None
            if value is None:
                text.append(" ")
            else:
                char = chr(value) if 32 <= value <= 126 else "."
                text.append(char, style=style)
        text.append("|\n")
    return text


class LoadFileScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading S19/HEX files."""
    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load file (S19/HEX):"),
            Input(placeholder="C:\\path\\to\\file.s19 or .hex", id="load_path"),
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


class LoadA2LScreen(ModalScreen[Optional[Path]]):
    """Modal dialog for loading an A2L file."""
    def compose(self) -> ComposeResult:
        yield Container(
            Label("Load A2L file:"),
            Input(placeholder="C:\\path\\to\\file.a2l", id="a2l_path"),
            Container(
                Button("Load", id="a2l_ok"),
                Button("Cancel", id="a2l_cancel"),
                id="load_buttons",
            ),
            id="load_dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "a2l_cancel":
            self.dismiss(None)
            return
        if event.button.id == "a2l_ok":
            value = self.query_one("#a2l_path", Input).value.strip()
            if not value:
                return
            self.dismiss(Path(value))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "project_list":
            return
        label_widget = event.item.query_one(Label)
        name = label_widget.text if hasattr(label_widget, "text") else str(label_widget)
        self.dismiss(name)


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
        grid-size: 3 2;
        grid-columns: 2fr 1fr 2fr;
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

    #alt_actions_panel {
        border: round $primary;
        padding: 1;
        row-span: 2;
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

    #alt_hex_controls {
        layout: horizontal;
        height: auto;
        padding-bottom: 1;
    }

    #alt_search_input, #alt_goto_input {
        width: 1fr;
    }

    #a2l_scroll {
        height: 100%;
        overflow: auto;
    }

    #a2l_tags_scroll {
        height: 100%;
        overflow: auto;
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
        ("a", "load_a2l", "Load A2L"),
        ("r", "refresh_files", "Refresh workarea"),
        ("o", "open_workarea", "Open workarea"),
        ("s", "save_project", "Save project"),
        ("p", "load_project", "Load project"),
        ("j", "dump_a2l_json", "Dump A2L JSON"),
        ("1", "view_main", "Main view"),
        ("2", "view_alt", "Alt view"),
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
                ScrollableContainer(
                    Static("", id="a2l_tags_view", markup=False),
                    id="a2l_tags_scroll",
                ),
                id="alt_tags_panel",
            ),
            Container(
                Label("Actions", id="alt_actions_title"),
                Static("Placeholder content", id="alt_content_2"),
                id="alt_actions_panel",
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
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_files()
        if self.load_path:
            self.logger.info("Startup load requested: %s", self.load_path)
            self.load_from_path(self.load_path)

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
        """Open file picker for S19/HEX."""
        self.logger.info("Load file action triggered.")
        self.push_screen(LoadFileScreen(), self._handle_load_dialog)

    def action_load_a2l(self) -> None:
        """Open file picker for A2L."""
        self.logger.info("Load A2L action triggered.")
        self.push_screen(LoadA2LScreen(), self._handle_a2l_dialog)

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
        main_layout.remove_class("hidden")
        alt_layout.add_class("hidden")

    def action_view_alt(self) -> None:
        """Switch to the alternate view."""
        main_layout = self.query_one("#main_layout")
        alt_layout = self.query_one("#alt_layout")
        main_layout.add_class("hidden")
        alt_layout.remove_class("hidden")

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

    def _handle_a2l_dialog(self, path: Optional[Path]) -> None:
        if path is None:
            self.logger.info("Load A2L canceled.")
            return
        self.load_a2l_from_path(path)

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

    def _handle_load_dialog(self, path: Optional[Path]) -> None:
        if path is None:
            return
        self.load_from_path(path)

    def load_from_path(self, path: Path) -> None:
        """Load S19/HEX file into temp and render views."""
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

    def _load_from_item(self, item: ListItem) -> None:
        label_widget = item.query_one(Label)
        if hasattr(label_widget, "text"):
            filename = label_widget.text
        else:
            filename = str(label_widget)
        candidate = self.workarea / filename
        if candidate.exists():
            self.logger.info("Loading from workarea selection: %s", candidate)
            self.load_selected_file(candidate)

    def _jump_to_section(self, item: ListItem) -> None:
        section_range = getattr(item, "data", None)
        if section_range:
            start, _ = section_range
            self.update_hex_view(start)

    def load_selected_file(self, path: Path, a2l_files: Optional[list[Path]] = None) -> None:
        """Parse S19/HEX and update all dependent views."""
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
                tag_checks = validate_a2l_tags(a2l_data.get("tags", []), mem_map) if a2l_data else None
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
            else:
                hex_file = IntelHexFile(str(path))
                mem_map = dict(hex_file.memory)
                row_bases = build_row_bases(mem_map)
                ranges = hex_file.get_ranges()
                range_validity = build_range_validity_hex(hex_file, ranges)
                errors = hex_file.get_errors()
                a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
                a2l_data = parse_a2l_file(a2l_path) if a2l_path else self.current_a2l_data
                tag_checks = validate_a2l_tags(a2l_data.get("tags", []), mem_map) if a2l_data else None
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

    def update_a2l_view(self) -> None:
        """Render the A2L summary view."""
        a2l_view = self.query_one("#a2l_view", Static)
        if not self.current_a2l_data:
            a2l_view.update("No A2L loaded.")
            self.update_a2l_tags_view([])
            return
        tag_checks = None
        if self.current_file:
            tag_checks = validate_a2l_tags(self.current_a2l_data.get("tags", []), self.current_file.mem_map)
        a2l_view.update(render_a2l_view(self.current_a2l_data, tag_checks))
        self.update_a2l_tags_view(self.current_a2l_data.get("tags", []))
    def update_a2l_tags_view(self, tags: list[dict]) -> None:
        a2l_tags_view = self.query_one("#a2l_tags_view", Static)
        if not tags:
            a2l_tags_view.update("No A2L tags.")
            return
        rows = []
        for tag in tags[:400]:
            addr = tag.get("address")
            length = tag.get("length")
            addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
            len_text = str(length) if isinstance(length, int) else "n/a"
            name_text = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
            rows.append((name_text, addr_text, len_text))

        name_width = min(48, max(len("Tag"), *(len(row[0]) for row in rows)))
        addr_width = max(len("Address"), *(len(row[1]) for row in rows))
        len_width = max(len("Length"), *(len(row[2]) for row in rows))

        header = f"{'Tag'.ljust(name_width)} | {'Address'.ljust(addr_width)} | {'Length'.ljust(len_width)}"
        lines = [header]
        for name_text, addr_text, len_text in rows:
            trimmed_name = name_text[:name_width].ljust(name_width)
            lines.append(f"{trimmed_name} | {addr_text.ljust(addr_width)} | {len_text.ljust(len_width)}")
        a2l_tags_view.update("\n".join(lines))

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
        elif event.button.id == "alt_search_button":
            self._handle_search_alt()
        elif event.button.id == "alt_goto_button":
            self._handle_goto_alt()

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
        # Ensure we always show 4 log lines, newest on bottom.
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

    parser = argparse.ArgumentParser(description="S19/HEX TUI Viewer")
    parser.add_argument("--load", help="Optional path to load at startup")
    args = parser.parse_args()
    load_path = Path(args.load) if args.load else None
    app = S19TuiApp(load_path=load_path)
    app.run()
