from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import shutil

from textual.app import App, ComposeResult
from textual.containers import Container
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
MAX_HEX_BYTES = 4096
HEX_WIDTH = 16


@dataclass
class LoadedFile:
    path: Path
    file_type: str
    mem_map: Dict[int, int]
    ranges: List[Tuple[int, int]]
    range_validity: List[bool]
    errors: List[dict]


def ensure_workarea(base_dir: Path) -> Path:
    workarea = base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    workarea.mkdir(parents=True, exist_ok=True)
    return workarea


def copy_into_workarea(source: Path, workarea: Path) -> Path:
    workarea.mkdir(parents=True, exist_ok=True)
    target = workarea / source.name
    if target.exists():
        stem = source.stem
        suffix = source.suffix
        counter = 1
        while True:
            candidate = workarea / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1
    shutil.copy2(source, target)
    return target


def build_mem_map_s19(s19: S19File) -> Dict[int, int]:
    mem_map: Dict[int, int] = {}
    for record in s19.records:
        for offset, value in enumerate(record.data):
            mem_map[record.address + offset] = value
    return mem_map


def build_range_validity_s19(s19: S19File, ranges: List[Tuple[int, int]]) -> List[bool]:
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
    has_errors = len(hex_file.get_errors()) > 0
    return [not has_errors for _ in ranges]


def render_hex_view(mem_map: Dict[int, int]) -> str:
    if not mem_map:
        return "No data available."
    addresses = sorted(mem_map.keys())
    start_addr = addresses[0]
    end_addr = addresses[-1]

    lines: List[str] = []
    bytes_rendered = 0

    for row_addr in range(start_addr - (start_addr % HEX_WIDTH), end_addr + 1, HEX_WIDTH):
        row_bytes: List[Optional[int]] = []
        has_data = False
        for offset in range(HEX_WIDTH):
            addr = row_addr + offset
            value = mem_map.get(addr)
            if value is not None:
                has_data = True
                bytes_rendered += 1
            row_bytes.append(value)

        if not has_data:
            continue

        hex_part = " ".join(f"{b:02X}" if b is not None else "  " for b in row_bytes)
        ascii_part = "".join(chr(b) if b is not None and 32 <= b <= 126 else "." for b in row_bytes)
        lines.append(f"0x{row_addr:08X}  {hex_part}  |{ascii_part}|")

        if bytes_rendered >= MAX_HEX_BYTES:
            lines.append(f"... output truncated at {MAX_HEX_BYTES} bytes ...")
            break

    return "\n".join(lines)


class LoadFileScreen(ModalScreen[Optional[Path]]):
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


class S19TuiApp(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 3 2;
        grid-columns: 1fr 1fr 2fr;
        grid-rows: 1fr 1fr;
        padding: 1;
        grid-gutter: 1;
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
    }

    #bottom_left {
        border: round $primary;
        padding: 1;
    }

    #bottom_right {
        border: round $primary;
        padding: 1;
    }

    #progress_bar {
        margin-top: 1;
    }

    #hex_view {
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
    """

    BINDINGS = [
        ("l", "load_file", "Load file"),
        ("r", "refresh_files", "Refresh workarea"),
        ("q", "quit", "Quit"),
    ]

    workarea: Path
    current_file: reactive[Optional[LoadedFile]] = reactive(None)

    def __init__(self, base_dir: Optional[Path] = None, load_path: Optional[Path] = None):
        super().__init__()
        self.base_dir = base_dir or Path.cwd()
        self.workarea = ensure_workarea(self.base_dir)
        self.load_path = load_path

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label("Workarea Files", id="files_title"),
            ListView(id="files_list"),
            id="files_panel",
        )
        yield Container(
            Label("Data Sections", id="sections_title"),
            ListView(id="sections_list"),
            id="sections_panel",
        )
        yield Container(
            Label("Hex View", id="hex_title"),
            Static("", id="hex_view"),
            id="hex_panel",
        )
        yield Container(Label("Bottom Left (reserved)"), id="bottom_left")
        yield Container(
            Label("Status", id="status_title"),
            Label("Ready.", id="status_text"),
            ProgressBar(total=100, id="progress_bar"),
            id="bottom_right",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_files()
        if self.load_path:
            self.load_from_path(self.load_path)

    def refresh_files(self) -> None:
        list_view = self.query_one("#files_list", ListView)
        list_view.clear()
        files = sorted(self.workarea.glob("*"))
        for item in files:
            if item.is_file():
                list_view.append(ListItem(Label(item.name)))

    def action_refresh_files(self) -> None:
        self.refresh_files()

    def action_load_file(self) -> None:
        self.push_screen(LoadFileScreen(), self._handle_load_dialog)

    def _handle_load_dialog(self, path: Optional[Path]) -> None:
        if path is None:
            return
        self.load_from_path(path)

    def load_from_path(self, path: Path) -> None:
        normalized = Path(str(path).strip().strip('"')).expanduser()
        if not normalized.exists():
            self.set_status(f"File not found: {normalized}")
            return
        if normalized.suffix.lower() not in {".s19", ".srec", ".hex", ".ihex"}:
            self.set_status(f"Unsupported file type: {normalized.suffix}")
            return
        self.set_progress(10, "Copying into workarea...")
        copied = copy_into_workarea(normalized, self.workarea)
        self.refresh_files()
        self.set_progress(50, f"Loading {copied.name}...")
        self.load_selected_file(copied)
        self.set_progress(100, f"Loaded {copied.name}")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "files_list":
            return
        label = event.item.query_one(Label).renderable
        filename = label.plain if hasattr(label, "plain") else str(label)
        candidate = self.workarea / filename
        if candidate.exists():
            self.load_selected_file(candidate)

    def load_selected_file(self, path: Path) -> None:
        suffix = path.suffix.lower()
        try:
            if suffix in {".s19", ".srec"}:
                s19 = S19File(str(path))
                mem_map = build_mem_map_s19(s19)
                ranges = s19._get_memory_ranges()
                range_validity = build_range_validity_s19(s19, ranges)
                errors = s19.get_errors()
                loaded = LoadedFile(
                    path=path,
                    file_type="s19",
                    mem_map=mem_map,
                    ranges=ranges,
                    range_validity=range_validity,
                    errors=errors,
                )
            else:
                hex_file = IntelHexFile(str(path))
                mem_map = dict(hex_file.memory)
                ranges = hex_file.get_ranges()
                range_validity = build_range_validity_hex(hex_file, ranges)
                errors = hex_file.get_errors()
                loaded = LoadedFile(
                    path=path,
                    file_type="hex",
                    mem_map=mem_map,
                    ranges=ranges,
                    range_validity=range_validity,
                    errors=errors,
                )
        except Exception as exc:
            self.set_status(f"Load failed: {exc}")
            return
        self.current_file = loaded
        self.update_sections()
        self.update_hex_view()
        self.set_status(f"Loaded {path.name}")

    def update_sections(self) -> None:
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
            sections.append(ListItem(label))

    def update_hex_view(self) -> None:
        hex_view = self.query_one("#hex_view", Static)
        if not self.current_file:
            hex_view.update("No file loaded.")
            return
        hex_view.update(render_hex_view(self.current_file.mem_map))

    def set_status(self, message: str) -> None:
        status_text = self.query_one("#status_text", Label)
        status_text.update(message)

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
