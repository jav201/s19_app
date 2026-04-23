"""
Textual TUI for S19/HEX inspection with optional A2L support.

High-level responsibilities:
- Manage a workarea for transient loads and saved projects.
- Load and parse S19/HEX data, build ranges, and render hex view.
- Load and minimally parse A2L files and show a readable summary.
- Enforce project rules (one data file + one A2L per project).
- Provide actions/bindings for common workflows and export helpers.
"""

from .a2l_extract import extract_a2l_tags
from .a2l_parse import parse_a2l_file
from .a2l_render import render_a2l_view
from .a2l_validate import validate_a2l_internal_issues, validate_a2l_tags
from .app import S19TuiApp, main
from .hexview import (
    FOCUS_CONTEXT_ROWS,
    HEX_WIDTH,
    MAX_HEX_BYTES,
    MAX_HEX_ROWS,
    SEARCH_ENCODING,
    address_in_sorted_ranges,
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
    build_sorted_range_index,
    find_string_in_mem,
    range_in_sorted_ranges,
    render_hex_view,
    render_hex_view_text,
)
from .models import LoadedFile
from .screens import LoadFileScreen, LoadProjectScreen, SaveProjectPayload, SaveProjectScreen
from .workspace import (
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    LOG_FILENAME,
    LOGS_SUBDIR,
    PROJECT_DATA_EXTENSIONS,
    S19_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WORKAREA_TEMP,
    copy_into_workarea,
    ensure_workarea,
    find_repo_root,
    resolve_input_path,
    sanitize_project_name,
    setup_logging,
    validate_project_files,
)

__all__ = [
    "A2L_EXTENSIONS",
    "FOCUS_CONTEXT_ROWS",
    "HEX_EXTENSIONS",
    "HEX_WIDTH",
    "LOG_FILENAME",
    "LOGS_SUBDIR",
    "LoadFileScreen",
    "LoadProjectScreen",
    "LoadedFile",
    "MAX_HEX_BYTES",
    "MAX_HEX_ROWS",
    "PROJECT_DATA_EXTENSIONS",
    "SEARCH_ENCODING",
    "S19TuiApp",
    "S19_EXTENSIONS",
    "SUPPORTED_EXTENSIONS",
    "SaveProjectPayload",
    "SaveProjectScreen",
    "WORKAREA_DIRNAME",
    "WORKAREA_SUBDIR",
    "WORKAREA_TEMP",
    "address_in_sorted_ranges",
    "build_mem_map_s19",
    "build_range_validity_hex",
    "build_range_validity_s19",
    "build_row_bases",
    "build_sorted_range_index",
    "copy_into_workarea",
    "ensure_workarea",
    "extract_a2l_tags",
    "find_repo_root",
    "find_string_in_mem",
    "main",
    "parse_a2l_file",
    "range_in_sorted_ranges",
    "render_a2l_view",
    "render_hex_view",
    "render_hex_view_text",
    "resolve_input_path",
    "sanitize_project_name",
    "setup_logging",
    "validate_a2l_tags",
    "validate_a2l_internal_issues",
    "validate_project_files",
]
