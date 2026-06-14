from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import Any, List, Optional

from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    Static,
)
from textual.widgets.data_table import RowDoesNotExist
from rich.text import Text

from ..core import S19File
from ..hexfile import IntelHexFile
from .a2l_parse import parse_a2l_file
from .hexview import (
    address_in_sorted_ranges,
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
    build_sorted_range_index,
    find_string_in_mem,
    render_hex_view_text,
)
from .command_bar import CommandBar, PaletteEntry
from .mac import parse_mac_file
from .models import LoadedFile, ProjectVariantSet
from .operations import get_operation, list_operation_ids
from .rail import Rail, RailItem
from .screens import (
    LoadFileScreen,
    LoadProjectScreen,
    OperationsScreen,
    ReportViewerScreen,
    SaveProjectPayload,
    SaveProjectScreen,
    SelectVariantScreen,
)
from .screens_directionb import (
    AbDiffPanel,
    BookmarksPlaceholder,
    EmptyStatePanel,
    MemoryMapPanel,
    PatchEditorPanel,
)
from .color_policy import css_class_for_severity
from ..validation import ValidationIssue, ValidationReport, ValidationSeverity
from .services.a2l_service import enrich_tags_and_render
from .services.change_service import ChangeActionResult, ChangeService
from .services.compare_service import (
    SOURCE_EXTERNAL,
    SOURCE_PROJECT_VARIANT,
    ImageSource,
    compare_images,
)
from .services.diff_report_service import (
    generate_diff_report,
    generate_diff_report_html,
)
from .services.load_service import build_loaded_hex, build_loaded_s19
from .services.report_service import (
    EXECUTION_SCOPE_TO_REPORT_MODE,
    REPORT_SOURCE_DEFAULT,
    REPORT_SOURCE_MANIFEST,
    ReportOptions,
    generate_project_report,
    list_project_reports,
)
from .services.validation_service import build_validation_report
from .services.variant_execution_service import (
    EXECUTION_SCOPES,
    SCOPE_ACTIVE,
    VariantExecutionResult,
    execute_project_variants,
    read_project_manifest,
)
from .workspace import (
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    S19_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    build_variant_set,
    copy_into_workarea,
    ensure_workarea,
    resolve_input_path,
    sanitize_project_name,
    setup_logging,
    validate_project_files,
)

#: The Patch Editor's routable action set (LLR-003.2) — the eight v2
#: actions of increment E3a extended by exactly one further action at E6,
#: ``execute_scope`` (the stated F-A-15 extension, LLR-006.6 — nine total).
#: A non-member action is reported as a status error, never a crash.
PATCH_ACTIONS_V2: frozenset[str] = frozenset(
    {
        "add_entry",
        "edit_entry",
        "remove_entry",
        "load_doc",
        "validate_doc",
        "apply_doc",
        "save_doc",
        "run_checks",
        "execute_scope",
    }
)


def _a2l_tag_in_memory_display(tag: dict) -> str:
    if not tag.get("memory_checked"):
        return "n/a"
    if tag.get("in_memory") is True:
        return "yes"
    return "no"


def _a2l_tag_unit_display(tag: dict) -> str:
    """
    Summary:
        Choose the best display unit for an A2L tag, preferring explicit ``UNIT`` then COMPU method unit.

    Args:
        tag (dict): Enriched A2L tag dictionary.

    Returns:
        str: Unit text for tables, find, and filter surfaces.

    Raises:
        None

    Data Flow:
        - Prefer ``tag["unit"]`` when present.
        - Fall back to ``tag["compu_method_unit"]`` from resolved ``COMPU_METHOD``.
        - Normalize absent values to an empty string.

    Dependencies:
        Uses:
        - none
        Used by:
        - ``S19TuiApp.update_a2l_tags_view``
        - ``S19TuiApp._a2l_tag_find_haystack``
        - ``S19TuiApp._tag_matches_filter``
    """
    explicit = tag.get("unit")
    if explicit not in (None, ""):
        return str(explicit)
    compu_unit = tag.get("compu_method_unit")
    return "" if compu_unit in (None, "") else str(compu_unit)


def _a2l_tag_row_severity(tag: dict) -> ValidationSeverity:
    if not tag.get("schema_ok", True):
        return ValidationSeverity.ERROR
    if tag.get("memory_checked") and tag.get("in_memory") is True:
        return ValidationSeverity.OK
    if tag.get("memory_checked") and tag.get("in_memory") is False:
        return ValidationSeverity.INFO
    if tag.get("virtual") or str(tag.get("source") or "").lower() == "formula":
        return ValidationSeverity.INFO
    return ValidationSeverity.NEUTRAL


MAX_SECTIONS_OUT_OF_RANGE = 50
"""Max MAC out-of-range rows the Sections panel renders before adding a truncation marker."""


MAX_SECTIONS_PRIMARY_RANGES = 200
"""Max primary memory-range rows the Sections panel mounts before adding a truncation marker.

Textual's ``ListView.append`` incurs per-item DOM + CSS cost, so uncapped range lists
with thousands of entries can stall the main thread for many seconds. Capping keeps the
install step bounded regardless of how fragmented the S19/HEX image is.
"""


@dataclass
class PreparedLoad:
    """
    Summary:
        Bundle of pre-computed artifacts produced by the load worker so the main UI
        thread only needs to install them onto widgets.

    Args:
        loaded (LoadedFile): Parsed file payload ready to become ``current_file``.
        precomputed (bool): True when the worker populated MAC cache/validation fields.
        mac_cache_key (Optional[tuple]): Cache key that matches the one ``update_mac_view``
            will recompute, so MAC rendering treats the worker output as a cache hit.
        mac_rows / mac_meta / mac_summary / mac_coverage_line: MAC table payload mirroring
            the fields normally populated by ``_build_mac_view_cache``.
        validation_report / validation_issues: Cross-artifact validation output.
        mac_highlights (frozenset[int]): Addresses flagged for orange hex overlay.
        mac_out_of_range (list[int]): Sorted MAC addresses outside the primary image.
        bases_set (Optional[frozenset[int]]): ``frozenset(row_bases)`` for fast hex render.
        a2l_enriched_tags / a2l_enriched_key / a2l_summary_lines: Precomputed A2L enrichment
            state ready to install into ``_a2l_enriched_*`` caches.

    Data Flow:
        - Built inside ``S19TuiApp._prepare_load_payload`` on the worker thread.
        - Consumed by ``S19TuiApp._apply_prepared_load`` on the Textual main thread.

    Dependencies:
        Used by:
            - ``S19TuiApp._start_load_worker``
            - ``S19TuiApp._apply_loaded_file`` (synchronous fallback)
    """

    loaded: LoadedFile
    precomputed: bool = False
    mac_cache_key: Optional[tuple] = None
    mac_rows: list = field(default_factory=list)
    mac_meta: list = field(default_factory=list)
    mac_summary: dict = field(default_factory=dict)
    mac_coverage_line: Optional[str] = None
    validation_report: Optional[ValidationReport] = None
    validation_issues: list = field(default_factory=list)
    mac_highlights: frozenset = field(default_factory=frozenset)
    mac_out_of_range: list = field(default_factory=list)
    bases_set: Optional[frozenset] = None
    a2l_enriched_tags: list = field(default_factory=list)
    a2l_enriched_key: Optional[tuple] = None
    a2l_summary_lines: list = field(default_factory=list)
    # DataTable-oriented precompute (populated by the load worker):
    # - ``mac_widths``: 8-tuple of column widths matching the historical inline computation
    #   in ``update_mac_view`` so the main thread never rescans full row vectors.
    # - ``mac_cell_rows``: list of 8-string tuples ready to hand to ``DataTable.add_rows``.
    # - ``mac_cell_styles``: parallel list of severity style strings per row.
    # - ``issue_cell_rows``: list of 6-string tuples for the Issues DataTable.
    # - ``issue_cell_styles``: parallel severity style strings per issue row.
    mac_widths: Optional[tuple] = None
    mac_cell_rows: list = field(default_factory=list)
    mac_cell_styles: list = field(default_factory=list)
    issue_cell_rows: list = field(default_factory=list)
    issue_cell_styles: list = field(default_factory=list)


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
        - Fail parse rows to invalid.
        - When A2L is absent or the tag name is missing, mark neutral.
        - Keep out-of-image rows as non-hard findings (info).
        - When the name is absent from A2L, mark warning.
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
        return "OUT_OF_IMAGE", ValidationSeverity.INFO.value
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


_MAC_COLUMN_HEADERS: tuple[str, ...] = (
    "Tag",
    "Address",
    "InA2L",
    "InMem",
    "Status",
    "SourceLine",
    "ParseErr",
    "A2LMatch",
)


_SEVERITY_TO_RICH_STYLE: dict[ValidationSeverity, str] = {
    ValidationSeverity.OK: "green",
    ValidationSeverity.ERROR: "red",
    ValidationSeverity.WARNING: "orange3",
    ValidationSeverity.INFO: "white",
    ValidationSeverity.NEUTRAL: "grey70",
}


def _severity_style(severity: ValidationSeverity) -> str:
    """
    Summary:
        Map a ``ValidationSeverity`` to a Rich-compatible style string usable by
        ``rich.text.Text`` cells inside a Textual ``DataTable``.

    Args:
        severity (ValidationSeverity): Severity to convert.

    Returns:
        str: Style string (e.g. ``"red"``, ``"green"``). Empty string when unknown.

    Dependencies:
        Used by:
            - ``precompute_mac_datatable_payload``
            - ``precompute_issue_datatable_payload``
    """
    return _SEVERITY_TO_RICH_STYLE.get(severity, "")


def precompute_mac_datatable_payload(
    mac_rows: list[tuple],
    mac_meta: list[dict],
) -> tuple[tuple[int, ...], list[tuple[str, ...]], list[str]]:
    """
    Summary:
        Compute the column widths, row tuples, and per-row severity styles the MAC
        DataTable needs, using the raw row vectors produced by
        ``_compute_mac_view_payload`` so the work happens off the UI thread.

    Args:
        mac_rows (list[tuple]): 8-tuples in display order (Tag, Address, InA2L,
            InMem, Status, SourceLine, ParseErr, A2LMatch).
        mac_meta (list[dict]): Parallel metadata with ``severity`` keys.

    Returns:
        tuple[tuple[int, ...], list[tuple[str, ...]], list[str]]:
            ``(widths, cell_rows, styles)`` where ``widths`` has length 8 and mirrors
            the historical inline width computation in ``update_mac_view``, and
            ``styles`` is a Rich style string per row.

    Data Flow:
        - Single pass over ``mac_rows`` to compute per-column ``max(len(cell))``.
        - Clamp Tag/ParseErr/A2LMatch to 48 chars matching the current renderer.
        - Copy rows verbatim into the returned cell-row list (strings as-is).
        - Pull severity from ``mac_meta`` and map via ``_severity_style``.

    Dependencies:
        Uses:
            - ``_severity_style``
        Used by:
            - ``S19TuiApp._prepare_load_payload``
    """
    if not mac_rows:
        widths = tuple([len(label) for label in _MAC_COLUMN_HEADERS])
        return widths, [], []
    cell_rows: list[tuple[str, ...]] = [tuple(str(cell) for cell in row) for row in mac_rows]
    col_count = len(_MAC_COLUMN_HEADERS)
    widths_list = [len(header) for header in _MAC_COLUMN_HEADERS]
    for row in cell_rows:
        for idx in range(col_count):
            if idx < len(row):
                cell_len = len(row[idx])
                if cell_len > widths_list[idx]:
                    widths_list[idx] = cell_len
    # Clamp the three wide textual columns to match the historical inline computation.
    widths_list[0] = min(widths_list[0], 48)  # Tag
    widths_list[6] = min(widths_list[6], 48)  # ParseErr
    widths_list[7] = min(widths_list[7], 48)  # A2LMatch
    styles: list[str] = []
    for meta in mac_meta or []:
        severity = meta.get("severity") if isinstance(meta, dict) else None
        if isinstance(severity, ValidationSeverity):
            styles.append(_severity_style(severity))
        else:
            styles.append("")
    # Pad styles list to row count if meta was shorter than rows.
    while len(styles) < len(cell_rows):
        styles.append("")
    return tuple(widths_list), cell_rows, styles


def precompute_issue_datatable_payload(
    issues: list[ValidationIssue],
) -> tuple[list[tuple[str, ...]], list[str]]:
    """
    Summary:
        Format validation issues into ready-to-render 7-tuple cell rows and per-row
        severity styles so the main thread only calls ``DataTable.add_rows``.

    Args:
        issues (list[ValidationIssue]): Validation issues from the worker.

    Returns:
        tuple[list[tuple[str, ...]], list[str]]: ``(cell_rows, styles)`` where each
        cell row is ``(severity, code, artifact, symbol, address, line, message)``.

    Data Flow:
        - Iterate issues once.
        - Format address as ``0x%08X`` and line number as str when available.
        - Map severity enum to a Rich style string for the first cell.

    Dependencies:
        Uses:
            - ``_severity_style``
        Used by:
            - ``S19TuiApp._prepare_load_payload``
    """
    cell_rows: list[tuple[str, ...]] = []
    styles: list[str] = []
    for issue in issues or []:
        symbol = issue.symbol or "-"
        addr = f"0x{issue.address:08X}" if isinstance(issue.address, int) else "-"
        line_no = str(issue.line_number) if isinstance(issue.line_number, int) else "-"
        cell_rows.append(
            (
                issue.severity.value.upper(),
                str(issue.code or ""),
                str(issue.artifact or ""),
                symbol,
                addr,
                line_no,
                str(issue.message or ""),
            )
        )
        styles.append(_severity_style(issue.severity))
    return cell_rows, styles


class S19TuiApp(App):
    """Main TUI app with workarea, project management, and views."""

    TITLE = "Hex Edit Tool"
    CSS_PATH = "styles.tcss"

    # Direction B keymap (batch-02 keymap-proposal.md, owner-approved).
    # Rail keys 1-8 route screens via `action_show_screen`; the legacy
    # `1`/`2`/`3` view-toggle meaning is intentionally superseded (LLR-004.4).
    # `ctrl+d` cycles layout density (LLR-006.1). `ctrl+k` / `/` / `g` focus
    # the command-bar palette / find / go-to (LLR-004.1/004.2/004.3). The
    # `ctrl+l` / `ctrl+s` aliases keep load/save footer-discoverable and
    # operable while a command-bar input holds focus (keymap proposal §2);
    # the legacy unmodified `l`/`r`/`o`/`s`/`p`/`j` and the rail digits
    # `1`-`8` stay reachable but `show=False` so the footer is not crowded.
    # `Binding(..., show=False)` is the Textual form for an un-shown key.
    # The four `ctrl+*` bindings are `priority=True` so they stay live while
    # a command-bar `Input` is focused (keymap §4 — modified keys stay live);
    # without this the focused `Input`'s own `ctrl+k` / `ctrl+d` line-editing
    # bindings would shadow them.
    BINDINGS = [
        Binding("ctrl+k", "focus_palette", "Palette", priority=True),
        Binding("ctrl+d", "cycle_density", "Density", priority=True),
        Binding("ctrl+l", "load_file", "Load", priority=True),
        Binding("ctrl+s", "save_project", "Save", priority=True),
        ("slash", "focus_find", "Find"),
        ("g", "focus_goto", "Go-to"),
        ("q", "quit", "Quit"),
        Binding("l", "load_file", "Load file", show=False),
        Binding("r", "refresh_files", "Refresh workarea", show=False),
        Binding("o", "open_workarea", "Open workarea", show=False),
        Binding("s", "save_project", "Save project", show=False),
        Binding("p", "load_project", "Load project", show=False),
        Binding("v", "select_variant", "Select variant", show=False),
        Binding("j", "dump_a2l_json", "Dump A2L JSON", show=False),
        Binding("t", "view_reports", "View reports", show=False),
        Binding("x", "operations_view", "Operations", show=False),
        Binding("1", "show_screen('workspace')", "Workspace", show=False),
        Binding("2", "show_screen('a2l')", "A2L Explorer", show=False),
        Binding("3", "show_screen('mac')", "MAC View", show=False),
        Binding("4", "show_screen('map')", "Memory Map", show=False),
        Binding("5", "show_screen('issues')", "Issues Report", show=False),
        Binding("6", "show_screen('patch')", "Patch Editor", show=False),
        Binding("7", "show_screen('diff')", "A2B Diff", show=False),
        Binding("8", "show_screen('bookmarks')", "Bookmarks", show=False),
        ("plus", "page_next_context", "Page+"),
        ("minus", "page_prev_context", "Page-"),
        ("comma", "hex_page_prev", "Hex-"),
        ("period", "hex_page_next", "Hex+"),
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
        "raw_value",
        "physical_value",
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
    viewer_page_size_max: int = 200
    viewer_page_size_options: tuple[int, ...] = (25, 50, 100, 150, 200)
    a2l_tags_page_size: int = 200
    mac_records_page_size: int = 100
    hex_rows_page_size: int = 200
    a2l_summary_window_size: int = 500
    a2l_tag_hex_highlight_max_bytes: int = 4096
    validation_issue_filter_mode: str = "all"
    validation_issues_page_size: int = 200

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
        self._validation_issues_window_start: int = 0
        self.current_project_dir: Optional[Path] = None
        self._mac_window_start: int = 0
        self._mac_view_cache_key: Optional[tuple[Any, ...]] = None
        self._mac_view_cache_rows: list[tuple[str, str, str, str, str, str, str, str]] = []
        self._mac_view_cache_meta: list[dict[str, Any]] = []
        self._mac_view_cache_summary: dict[str, int] = {}
        self._mac_view_cache_coverage_line: Optional[str] = None
        self._mac_view_cache_widths: Optional[tuple[int, ...]] = None
        self._mac_view_cache_cell_rows: list[tuple[str, ...]] = []
        self._mac_view_cache_cell_styles: list[str] = []
        self._validation_issue_cell_rows: list[tuple[str, ...]] = []
        self._validation_issue_cell_styles: list[str] = []
        # Per-DataTable maps from visible row_key back to the underlying record so
        # the shared ``on_data_table_row_selected`` handler can jump correctly.
        self._mac_row_key_to_address: dict[str, int] = {}
        self._issue_row_key_to_index: dict[str, int] = {}
        self._a2l_row_key_to_tag: dict[str, dict[str, Any]] = {}
        self._hex_window_start: int = 0
        # First-visible row-base address caches for the alt / mac hex panes,
        # written by ``update_alt_hex_view`` / ``update_mac_hex_view`` and read
        # by ``_first_visible_hex_address`` (LLR-001.3 / LLR-001.4).
        self._alt_first_visible_address: Optional[int] = None
        self._mac_first_visible_address: Optional[int] = None
        # Per-view goto focus addresses, set by ``_apply_goto`` on a valid hit and
        # rendered as a plain-text ``> `` marker on the focus row by
        # ``render_hex_view_text``. Cleared on the per-view triggers enumerated in
        # LLR-003.6 (pagination, new search, parse-error goto, tag/record selection,
        # file load/unload). Persist across tab switches.
        self._goto_focus_address: Optional[int] = None
        self._alt_goto_focus_address: Optional[int] = None
        self._mac_goto_focus_address: Optional[int] = None
        #: Patch Editor change-list orchestration — owns the change-list and
        #: sequences the ``cdfx``-package calls (LLR-007.5 / C-8).
        self._change_service = ChangeService()
        #: Multi-variant project state (LLR-005.5/005.6): the active project's
        #: ordered S19/HEX variant inventory, or ``None`` when no project is
        #: active. Built by ``workspace.build_variant_set`` on project
        #: load/save and updated on variant switch / variant append.
        self._variant_set: Optional[ProjectVariantSet] = None
        #: Most recent A↔B comparison result, retained so the diff-report
        #: trigger (LLR-005.4) can report the same comparison the panel shows.
        self._diff_last_result: Optional[Any] = None
        #: Variant id to stamp onto the next applied primary ``LoadedFile``.
        #: Set on the main thread immediately before a load dispatch and
        #: consumed by ``_apply_prepared_load`` on the main thread, so the
        #: parse worker signature stays untouched and the worker never reads
        #: this field (LLR-005.4 thread contract). Cleared on load failure.
        self._pending_variant_id: Optional[str] = None
        #: Most recent ``execute_scope`` outcome retained for "generate
        #: report from last execution" (E8 / LLR-008.5):
        #: ``(project_dir, scope, assignment_source, results)``. The
        #: results carry their captured post-change mem_maps
        #: (``capture_mem_maps=True``), making this the app's ONLY mem_map
        #: retention point (the E7 risk item). Retention is bounded three
        #: ways: REPLACED by every new execution run, IGNORED (treated as
        #: absent) when the active project directory differs at generation
        #: time, and DROPPED (reset to ``None``) immediately after a
        #: successful report generation.
        self._last_execution: Optional[
            tuple[Path, str, str, List[VariantExecutionResult]]
        ] = None
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

    def _flush_logger(self) -> None:
        """
        Summary:
            Flush every handler on ``self.logger`` so phase-boundary lines are persisted
            to disk even if the next step hangs the thread.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Iterate ``self.logger.handlers`` and call ``flush`` guarded by ``try/except``.
            - Silently ignore handlers that cannot flush (e.g., after shutdown).

        Dependencies:
            Used by:
                - ``_handle_load_dialog`` / ``load_from_path`` / ``_parse_loaded_file``
                - ``_load_mac_file`` / ``_prepare_load_payload`` / ``_start_load_worker``
                - ``_apply_prepared_load`` phase chain steps
        """
        for handler in getattr(self.logger, "handlers", []):
            try:
                handler.flush()
            except Exception:
                pass

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
        ps = self._clamp_viewer_page_size(self.a2l_tags_page_size)
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
        ps = self._clamp_viewer_page_size(self.mac_records_page_size)
        if total_records <= 0 or ps <= 0:
            return 0
        aligned = (max(0, self._mac_window_start) // ps) * ps
        max_start = max(0, ((total_records - 1) // ps) * ps)
        return max(0, min(aligned, max_start))

    def _clamp_viewer_page_size(self, value: int) -> int:
        """
        Summary:
            Normalize viewer page-size settings into the allowed configured range.

        Args:
            value (int): Requested per-view page-size value.

        Returns:
            int: Clamped page-size in ``[1, viewer_page_size_max]``.

        Data Flow:
            - Coerce non-positive values to ``1``.
            - Clamp upper bound to ``viewer_page_size_max``.

        Dependencies:
            Used by:
                - Settings menu application handlers
        """
        return max(1, min(int(value), self.viewer_page_size_max))

    def _is_layout_visible(self, layout_id: str) -> bool:
        """Return True when a layout container is currently visible."""
        return "hidden" not in self.query_one(layout_id).classes

    def _active_view_name(self) -> str:
        """
        Summary:
            Report which legacy view (``main`` / ``alt`` / ``mac``) is the
            visible Direction B rail screen.

        Args:
            None

        Returns:
            str: ``"alt"`` when A2L Explorer is visible, ``"mac"`` when MAC
            View is visible, otherwise ``"main"`` (Workspace or any other
            rail screen).

        Data Flow:
            - Reads the ``.hidden`` class on the ``#screen_a2l`` /
              ``#screen_mac`` rail screen containers.

        Dependencies:
            Used by:
                - The paging actions (``action_page_*``, ``action_hex_page_*``)
                  that route by active view.
        """
        if self._is_layout_visible("#screen_a2l"):
            return "alt"
        if self._is_layout_visible("#screen_mac"):
            return "mac"
        return "main"

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
        """
        Summary:
            Lay out the Direction B app shell: a header, the command-bar and
            rail mount slots, an 8-child ``#workspace_body`` of ``.hidden``-
            toggled rail screen containers, and a footer.

        Args:
            None

        Returns:
            ComposeResult: The Textual widget tree for ``S19TuiApp``.

        Data Flow:
            - Screens 1-3 (Workspace / A2L / MAC) are Direction B two/three-
              pane re-layouts (increments 5-6); every ``update_*`` renderer
              keeps its widget ids since each pane reuses the pre-batch
              widget subtrees verbatim.
            - Screen 5 (Issues Report) is a dedicated rail screen
              (increment 7) holding the Issues ``DataTable`` + filters +
              summary promoted out of the old Workspace Status tile.
            - Screen 4 (Memory Map) renders a read-only coverage map of the
              loaded image, and screen 8 (Bookmarks) shows a neutral
              "coming soon" placeholder (increment 9).
            - Screen 6 (Patch Editor) is an inert before/after view shell
              and screen 7 (A2B Diff) is a static three-column placeholder
              (increment 10); neither wires patch or diff logic.
            - The persistent ``#workspace_status_bar`` (above the footer)
              hosts the re-homed status text, progress bar and log-tail
              labels — the renderer targets the old Status tile carried.
            - Only ``#screen_workspace`` is visible at startup; the other
              seven screen containers carry the ``.hidden`` class.

        Dependencies:
            Uses:
                - ``Rail``
            Used by:
                - Textual ``App`` mount lifecycle
        """
        yield Header()
        # Direction B command bar — palette (Ctrl+K), find (/), go-to (g)
        # and the project/A2L context labels relocated from the old Status
        # tile (LLR-011.3). The palette command list is built 1:1 from
        # `BINDINGS` so every action is reachable (LLR-003.2).
        yield Container(
            CommandBar(self._build_palette_entries()),
            id="command_bar_slot",
        )
        yield Container(
            ListView(id="settings_menu_list"),
            id="settings_menu",
            classes="hidden",
        )
        # Activity rail (left) + the 8-screen workspace body (right).
        # The rail emits `Rail.Selected`; `on_rail_selected` routes it.
        yield Horizontal(
            Container(Rail(active="workspace"), id="rail_slot"),
            Container(
                self._compose_screen_workspace(),
                self._compose_screen_a2l(),
                self._compose_screen_mac(),
                self._compose_screen_map(),
                self._compose_screen_issues(),
                self._compose_screen_patch(),
                self._compose_screen_diff(),
                self._compose_screen_bookmarks(),
                id="workspace_body",
            ),
            id="workspace_shell",
        )
        # Persistent status bar — the re-homed status text, progress bar and
        # log-tail labels that the old Workspace Status tile carried. Kept
        # above the footer so `set_status` / `set_file_status` / `set_progress`
        # / the log tail keep a stable target on every screen (increment 7).
        yield Container(
            Label("Ready.", id="status_text"),
            ProgressBar(total=100, id="progress_bar"),
            Label("", id="log_line_1"),
            Label("", id="log_line_2"),
            Label("", id="log_line_3"),
            Label("", id="log_line_4"),
            id="workspace_status_bar",
        )
        yield Footer()

    def _compose_screen_workspace(self) -> Container:
        """
        Summary:
            Build the Direction B Workspace rail screen (``#screen_workspace``)
            as a three-pane horizontal layout — left data ranges/sections,
            center hex view, right context — per LLR-008.1.

        Args:
            None

        Returns:
            Container: ``#screen_workspace`` holding ``#workspace_panes``
            (the three-pane ``Horizontal``) and an ``EmptyStatePanel``.
            Visible at startup (no ``.hidden`` class).

        Data Flow:
            - Center pane reuses the pre-batch hex subtree verbatim
              (``#hex_controls`` with ``#search_input`` / ``#goto_input`` /
              ``#search_button`` / ``#goto_button``, and ``#hex_scroll`` /
              ``#hex_view``) so ``update_hex_view``, ``_handle_goto``,
              ``_handle_search`` and the increment-4 command-bar adapters keep
              working unmodified (LLR-008.2 / C-1).
            - Left pane hosts ``#files_list`` (Workarea Files) and
              ``#sections_list`` — the latter is the ``update_sections``
              render target, unchanged.
            - Right context pane hosts ``#a2l_view`` (the A2L summary that
              ``update_a2l_view`` writes to), unchanged.
            - An ``EmptyStatePanel`` is composed alongside the panes;
              ``_apply_empty_state`` shows it (and hides ``#workspace_panes``)
              while no ``LoadedFile`` is present (LLR-002.3).

        Dependencies:
            Uses:
                - ``EmptyStatePanel``
            Used by:
                - ``compose``
        """
        _left_pane = Container(
            Label("Workarea Files", id="files_title"),
            ListView(id="files_list"),
            Label("Data Sections", id="sections_title"),
            ListView(id="sections_list"),
            id="ws_left",
            classes="db-pane",
        )
        _center_pane = Container(
            Label("Hex View", id="hex_title"),
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
            id="ws_center",
            classes="db-pane",
        )
        _right_pane = Container(
            Label("Context", id="a2l_title"),
            ScrollableContainer(
                Static("", id="a2l_view", markup=False),
                id="a2l_scroll",
            ),
            id="ws_right",
            classes="db-pane",
        )
        _panes = Horizontal(
            _left_pane,
            _center_pane,
            _right_pane,
            id="workspace_panes",
        )
        return Container(
            _panes,
            EmptyStatePanel(),
            id="screen_workspace",
            classes="db-screen",
        )

    def _compose_screen_issues(self) -> Container:
        """
        Summary:
            Build the Direction B Issues Report rail screen (``#screen_issues``)
            as a dedicated full screen carrying the validation Issues
            ``DataTable``, its severity filter row and the summary line —
            promoted out of the old Workspace Status tile (LLR-011.1).

        Args:
            None

        Returns:
            Container: ``#screen_issues`` holding the filter row
            (``#validation_issues_filters``), the Issues ``DataTable``
            (``#validation_issues_list``), the ``#validation_issues_summary``
            label and an ``EmptyStatePanel``. Hidden at startup.

        Data Flow:
            - Lifts the ``#validation_issues_filters`` / ``#validation_issues_list``
              / ``#validation_issues_summary`` subtree intact out of the
              former hidden ``#workspace_carryover`` container; every id
              ``update_validation_issues_view``, the ``issues_filter_*``
              button handlers and ``action_validation_issues_page_*`` query
              is preserved, so no renderer / paging / filter logic changes
              (LLR-011.2 / C-1).
            - An ``EmptyStatePanel`` is composed alongside; while no
              ``LoadedFile`` is present ``_apply_empty_state`` shows it and
              hides the Issues content (LLR-002.3).

        Dependencies:
            Uses:
                - ``EmptyStatePanel``
            Used by:
                - ``compose``
        """
        _issues_content = Container(
            Container(
                Button("Issues: All", id="issues_filter_all"),
                Button("Errors", id="issues_filter_error"),
                Button("Warnings", id="issues_filter_warning"),
                id="validation_issues_filters",
            ),
            DataTable(
                id="validation_issues_list", zebra_stripes=True, cursor_type="row"
            ),
            Label("", id="validation_issues_summary"),
            id="issues_content",
        )
        return Container(
            Label("Issues Report", classes="db-screen-title"),
            _issues_content,
            EmptyStatePanel(),
            id="screen_issues",
            classes="db-screen hidden",
        )

    def _compose_screen_map(self) -> Container:
        """
        Summary:
            Build the Direction B Memory Map rail screen (``#screen_map``) —
            a read-only coverage visualization of the loaded image's memory
            ranges and gaps (LLR-012.1).

        Args:
            None

        Returns:
            Container: ``#screen_map`` holding a title label, a scrollable
            ``MemoryMapPanel`` (the ``#map_content`` coverage view) and an
            ``EmptyStatePanel``. Hidden at startup.

        Data Flow:
            - The ``MemoryMapPanel`` is driven by ``update_memory_map``,
              which reads the already-computed ``LoadedFile.ranges`` and
              ``LoadedFile.range_validity`` — no coverage is computed here
              (LLR-012.1 / LLR-012.4).
            - An ``EmptyStatePanel`` is composed alongside; while no
              ``LoadedFile`` is present ``_apply_empty_state`` shows it and
              hides ``#map_content`` (LLR-002.3).

        Dependencies:
            Uses:
                - ``MemoryMapPanel``
                - ``EmptyStatePanel``
            Used by:
                - ``compose``
        """
        return Container(
            Label("Memory Map", classes="db-screen-title"),
            ScrollableContainer(
                MemoryMapPanel(),
                id="map_content",
            ),
            EmptyStatePanel(),
            id="screen_map",
            classes="db-screen hidden",
        )

    def _compose_screen_bookmarks(self) -> Container:
        """
        Summary:
            Build the Direction B Bookmarks rail screen (``#screen_bookmarks``)
            as a neutral "coming soon" placeholder — no persistence logic is
            wired (LLR-002.2 / LLR-012.4).

        Args:
            None

        Returns:
            Container: ``#screen_bookmarks`` holding a title label and a
            ``BookmarksPlaceholder`` static notice. Hidden at startup.

        Data Flow:
            - Static composition only. Activating the Bookmarks rail item
              shows this container; no bookmark state is read or written.

        Dependencies:
            Uses:
                - ``BookmarksPlaceholder``
            Used by:
                - ``compose``
        """
        return Container(
            Label("Bookmarks", classes="db-screen-title"),
            BookmarksPlaceholder(),
            id="screen_bookmarks",
            classes="db-screen hidden",
        )

    def _compose_screen_patch(self) -> Container:
        """
        Summary:
            Build the Direction B Patch Editor rail screen (``#screen_patch``)
            as the consolidated v2 change-flow editor — one entries table,
            both-kind entry inputs, the Load / Validate / Apply / Save /
            Run-checks control row and an empty state (batch-07 increment
            E3a, LLR-003.1).

        Args:
            None

        Returns:
            Container: ``#screen_patch`` holding a title label and a
            ``PatchEditorPanel``. Hidden at startup.

        Data Flow:
            - Composition only. The ``PatchEditorPanel`` is presentational —
              its controls emit ``PatchEditorPanel.ActionRequested`` messages
              that ``on_patch_editor_panel_action_requested`` routes to
              ``self._change_service``. No JSON / change-document model
              logic is built here (constraint C-7 / LLR-003.2).

        Dependencies:
            Uses:
                - ``PatchEditorPanel``
            Used by:
                - ``compose``
        """
        return Container(
            Label("Patch Editor", classes="db-screen-title"),
            PatchEditorPanel(),
            id="screen_patch",
            classes="db-screen hidden",
        )

    def on_patch_editor_panel_action_requested(
        self, event: PatchEditorPanel.ActionRequested
    ) -> None:
        """
        Summary:
            Route a Patch Editor control action to the change service and
            feed the shaped rows back to the screen — exactly the nine
            ``PATCH_ACTIONS_V2`` actions (the LLR-003.2 eight plus the E6
            ``execute_scope`` extension, LLR-006.6); a retired or unknown
            action is one status error, never a crash.

        Args:
            event (PatchEditorPanel.ActionRequested): The message a Patch
                Editor control posted — its ``action`` plus the current
                address / value / bytes / path input-field text.

        Returns:
            None

        Data Flow:
            - ``add_entry`` / ``edit_entry`` / ``remove_entry`` mutate the
              service's v2 document (both entry kinds).
            - ``load_doc`` / ``validate_doc`` / ``save_doc`` round-trip and
              re-validate the document; ``apply_doc`` runs the E2 engine
              and, with ≥1 applied entry, opens the save-back prompt (S19)
              or states HEX save-back is unsupported (LLR-002.7).
            - ``run_checks`` rides the E4 service seam and renders the
              LLR-004.5 display.
            - ``execute_scope`` hands the selector's scope to
              ``_trigger_execute_scope``, which guards on the UI thread and
              starts the E6 execution worker (LLR-006.6).
            - Every action's outcome and findings surface through
              ``_report_change_result`` / ``set_status``; an input error is
              caught and reported, never raised into the UI.
            - The entries table and the persistent declaration-fault area
              are re-rendered after every action (LLR-002.8).

        Dependencies:
            Uses:
                - ``ChangeService``
                - ``_compute_a2l_enriched_tags``
                - ``PatchEditorPanel.refresh_entries`` / ``refresh_issues``
                  / ``refresh_check_results`` / ``show_save_prompt``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        service = self._change_service
        loaded = self.current_file
        mem_map = loaded.mem_map if loaded is not None else None
        loaded_ranges = loaded.ranges if loaded is not None else None
        mac_records = loaded.mac_records if loaded is not None else None
        a2l_tags = self._compute_a2l_enriched_tags() or None
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        try:
            if event.action not in PATCH_ACTIONS_V2:
                self.set_status(
                    f"Patch Editor: unsupported action {event.action!r}"
                )
            elif event.action == "add_entry":
                service.add_entry(
                    event.address_text, event.value_text, event.bytes_text
                )
                self.set_status("Patch Editor: entry added.")
            elif event.action == "edit_entry":
                service.edit_entry(
                    event.address_text, event.value_text, event.bytes_text
                )
                self.set_status("Patch Editor: entry updated.")
            elif event.action == "remove_entry":
                service.remove_entry(event.address_text)
                self.set_status("Patch Editor: entry removed.")
            elif event.action == "load_doc":
                if not event.path_text.strip():
                    self.set_status(
                        "Patch Editor: enter a change-file path to load."
                    )
                else:
                    result = service.load(event.path_text, self.base_dir)
                    self._report_change_result(result)
            elif event.action == "validate_doc":
                self._report_change_result(service.validate(loaded_ranges))
            elif event.action == "apply_doc":
                variant_id = loaded.path.stem if loaded is not None else None
                summary = service.apply(
                    mem_map,
                    loaded_ranges,
                    mac_records,
                    a2l_tags,
                    variant_id=variant_id,
                )
                counts = summary.counts
                skipped = (
                    counts["skipped-partial"]
                    + counts["skipped-outside"]
                    + counts["skipped-no-image"]
                )
                self.set_status(
                    f"Apply: {counts['applied']} applied, "
                    f"{skipped} skipped, {counts['blocked']} blocked"
                )
                if counts["applied"] > 0 and loaded is not None:
                    if loaded.file_type == "s19":
                        panel.show_save_prompt(f"{variant_id}-patched.s19")
                    else:
                        self.set_status(
                            "HEX save-back not supported this batch"
                        )
            elif event.action == "save_doc":
                self._report_change_result(service.save(self.base_dir))
            elif event.action == "run_checks":
                result = service.run_checks(
                    mem_map, loaded_ranges, mac_records, a2l_tags
                )
                self._report_change_result(result)
                panel.refresh_check_results(
                    service.check_rows(), result.message
                )
            elif event.action == "execute_scope":
                self._trigger_execute_scope(event.scope_text or SCOPE_ACTIVE)
        except (ValueError, KeyError) as exc:
            self.set_status(f"Patch Editor: {exc}")

        panel.refresh_entries(service.rows(loaded_ranges))
        panel.refresh_issues(service.issue_lines())

    def on_patch_editor_panel_save_back_decision(
        self, event: PatchEditorPanel.SaveBackDecision
    ) -> None:
        """
        Summary:
            Handle the operator's answer to the post-apply save-back prompt
            (LLR-002.7 UI half): persist the patched image under the typed
            filename, or persist nothing on decline (``saved_path`` stays
            ``None``).

        Args:
            event (PatchEditorPanel.SaveBackDecision): The prompt outcome —
                the (possibly edited) filename, or ``None`` when declined.

        Returns:
            None

        Data Flow:
            - Hide the prompt either way.
            - Decline → one status line, no write.
            - Confirm → ``ChangeService.save_patched`` into the active
              project directory (work-area root when no project is active);
              the typed name passes the engine's F-S-01 sanitizer; the
              result and its findings surface on the status path.

        Dependencies:
            Uses:
                - ``ChangeService.save_patched``
                - ``_active_project_dir``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.hide_save_prompt()
        if event.filename is None:
            self.set_status("Patch Editor: save-back declined")
            return
        loaded = self.current_file
        if loaded is None:
            self.set_status("Patch Editor: no image loaded - nothing saved")
            return
        dest_dir = self._active_project_dir() or self.workarea
        result = self._change_service.save_patched(
            loaded.mem_map,
            loaded.ranges,
            dest_dir,
            event.filename,
            source_kind=loaded.file_type,
        )
        self._report_change_result(result)

    def _report_change_result(self, result: ChangeActionResult) -> None:
        """
        Summary:
            Surface a change-service action result and its issues on the
            status path (the LLR-003.2 issue-surfacing arm — the evolved
            ``_report_cdfx_result`` pattern).

        Args:
            result (ChangeActionResult): The outcome of a ``ChangeService``
                load / validate / save / save-back / run-checks call.

        Returns:
            None

        Data Flow:
            - Emit the result's summary message, then one status line per
              ``ValidationIssue`` so the engineer sees every finding.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``on_patch_editor_panel_action_requested``
                - ``on_patch_editor_panel_save_back_decision``
        """
        self.set_status(result.message)
        for issue in result.issues:
            self.set_status(
                f"[{issue.code}] {issue.severity.value}: {issue.message}"
            )

    def _trigger_execute_scope(self, scope: str) -> None:
        """
        Summary:
            UI-thread gate for the E6 ``execute_scope`` action (LLR-006.6):
            validate the scope and the project/variant context, pick the
            manifest-absent fallback file, and start the execution worker.

        Args:
            scope (str): The selector's scope token — one of
                ``EXECUTION_SCOPES`` (``active`` / ``all`` /
                ``assignments``).

        Returns:
            None

        Data Flow:
            - Refuse an unknown scope, a missing project directory, or an
              empty variant set with one status line each.
            - The manifest-absent fallback batch (LLR-006.1 default) is the
              change service's loaded document ``source_path`` when it has
              one — the file the operator loaded in the Patch Editor.
            - Hand off to ``_start_execute_scope_worker`` (thread worker) so
              long runs never freeze the UI; all execution work happens in
              ``services.variant_execution_service``.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``_start_execute_scope_worker``
            Used by:
                - ``on_patch_editor_panel_action_requested``
        """
        if scope not in EXECUTION_SCOPES:
            self.set_status(f"Execute: unknown scope {scope!r}")
            return
        project_dir = self._active_project_dir()
        variant_set = self._variant_set
        if project_dir is None or variant_set is None or not variant_set.variants:
            self.set_status("Execute: no project variants - load a project first.")
            return
        source_path = self._change_service.document.source_path
        fallback_batch = [source_path] if source_path is not None else []
        manifest_present = read_project_manifest(project_dir) is not None
        if not fallback_batch and not manifest_present:
            self.set_status(
                "Execute: no manifest and no loaded change/check file - "
                "nothing to execute."
            )
            return
        assignment_source = (
            REPORT_SOURCE_MANIFEST if manifest_present else REPORT_SOURCE_DEFAULT
        )
        self.set_status(f"Execute: scope '{scope}' started...")
        self._start_execute_scope_worker(
            project_dir, variant_set, scope, fallback_batch, assignment_source
        )

    @work(thread=True, exclusive=True, group="execute_scope")
    def _start_execute_scope_worker(
        self,
        project_dir: Path,
        variant_set: ProjectVariantSet,
        scope: str,
        fallback_batch: list[Path],
        assignment_source: str,
    ) -> None:
        """
        Summary:
            Off-thread E6 execution worker: run
            ``execute_project_variants`` and surface per-variant status
            lines between variants via ``call_from_thread`` (F-Q-18), then
            dispatch the result report to the UI thread.

        Args:
            project_dir (Path): The active project directory.
            variant_set (ProjectVariantSet): The project's variant
                inventory at trigger time.
            scope (str): The validated execution scope.
            fallback_batch (list[Path]): The manifest-absent default file
                list.
            assignment_source (str): The report-vocabulary token
                (``manifest`` / ``default``) recorded at trigger time for
                the E8 retention snapshot.

        Returns:
            None

        Data Flow:
            - The service parses each variant's image itself (LLR-006.3);
              this worker never touches ``current_file``.
            - ``capture_mem_maps=True`` pins each variant's post-change
              memory map onto its result so a later "generate report from
              last execution" (E8 / LLR-008.5) can hexdump without
              re-running; ``_report_execution_results`` owns the bounded
              retention.
            - Status lines and the final report run on the UI thread via
              ``call_from_thread``; a service-level crash surfaces as one
              status line, never an unhandled worker exception.

        Dependencies:
            Uses:
                - ``execute_project_variants``
                - ``call_from_thread`` / ``_report_execution_results``
            Used by:
                - ``_trigger_execute_scope``
        """
        try:
            results, manifest_issues = execute_project_variants(
                project_dir,
                variant_set,
                scope=scope,
                fallback_batch=fallback_batch,
                capture_mem_maps=True,
                status_callback=lambda message: self.call_from_thread(
                    self.set_status, message
                ),
            )
        except Exception as exc:
            self.logger.exception("Execute scope worker failed: %s", exc)
            self.call_from_thread(
                self.set_status, f"Execute failed: {type(exc).__name__}: {exc}"
            )
            return
        self.call_from_thread(
            self._report_execution_results,
            project_dir,
            scope,
            assignment_source,
            results,
            manifest_issues,
        )

    def _report_execution_results(
        self,
        project_dir: Path,
        scope: str,
        assignment_source: str,
        results: List[VariantExecutionResult],
        manifest_issues: List[ValidationIssue],
    ) -> None:
        """
        Summary:
            UI-thread report of an E6 execution run: retain the run as the
            "last execution" snapshot for E8 report generation, then one
            status line per manifest finding and per variant result, plus
            the closing aggregate line.

        Args:
            project_dir (Path): The executed project directory — pinned in
                the retention snapshot so a later project switch
                invalidates it.
            scope (str): The executed scope token.
            assignment_source (str): ``manifest`` / ``default`` (report
                vocabulary, recorded at trigger time).
            results (List[VariantExecutionResult]): The per-variant
                outcomes in execution order.
            manifest_issues (List[ValidationIssue]): The manifest's
                collected findings (containment skips, parse faults).

        Returns:
            None

        Data Flow:
            - ``_last_execution`` is REPLACED first (LLR-008.5 retention:
              results + their captured mem_maps live until the next run,
              a project switch, or a successful report generation drops
              them).
            - Manifest findings first (the F-S-03 skip visibility), then
              one ``ok``/``error`` line per variant with its change/check
              counts and diagnostics, then the run summary.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``_start_execute_scope_worker`` (via ``call_from_thread``)
        """
        self._last_execution = (project_dir, scope, assignment_source, results)
        for issue in manifest_issues:
            self.set_status(
                f"[{issue.code}] {issue.severity.value}: {issue.message}"
            )
        for result in results:
            line = (
                f"Variant '{result.variant_id}': {result.status} - "
                f"{len(result.change_summaries)} change, "
                f"{len(result.check_results)} check"
            )
            self.set_status(line)
            for diagnostic in result.diagnostics:
                self.set_status(
                    f"Variant '{result.variant_id}': {diagnostic}"
                )
        error_count = sum(1 for result in results if result.status == "error")
        self.set_status(
            f"Execute: scope '{scope}' finished - {len(results)} variant(s), "
            f"{error_count} error(s)"
        )

    def action_view_reports(self) -> None:
        """
        Summary:
            Open the read-only report viewer modal for the active project
            (LLR-008.1/008.3) — key-bound (``t``) and palette-reachable,
            NOT a 9th rail item (LLR-008.2).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bail with one neutral status line when no project is active.
            - ``list_project_reports`` supplies the newest-first listing
              (the F-Q-05 parsed sort key); the screen renders it verbatim
              and shows its own neutral empty state when it is empty.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``list_project_reports``
                - ``ReportViewerScreen`` / ``push_screen``
            Used by:
                - ``t`` keybinding / command palette entry
        """
        project_dir = self._active_project_dir()
        if project_dir is None:
            self.set_status("Reports: no active project - load a project first.")
            self.logger.info("View reports action triggered with no project.")
            return
        reports = list_project_reports(project_dir)
        project_name = self.current_project or project_dir.name
        self.logger.info(
            "View reports action. project=%s count=%d", project_name, len(reports)
        )
        self.push_screen(ReportViewerScreen(project_name, reports))

    def on_report_viewer_screen_generate_requested(
        self, message: ReportViewerScreen.GenerateRequested
    ) -> None:
        """
        Summary:
            Route the viewer's Generate request to the generation flow
            (LLR-008.5) — pure dispatch, no report logic here.

        Args:
            message (ReportViewerScreen.GenerateRequested): Carries the
                collected ``context_bytes``.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_trigger_generate_report``
            Used by:
                - ``ReportViewerScreen`` (bubbled message)
        """
        self._trigger_generate_report(message.context_bytes)

    def _trigger_generate_report(self, context_bytes: int) -> None:
        """
        Summary:
            UI-thread gate for E8 report generation (LLR-008.5): reuse the
            retained last-execution results when they belong to the active
            project, otherwise run the active-variant scope first — the
            minimal coherent flow, announced with a status line rather
            than a second confirmation dialog.

        Args:
            context_bytes (int): The collected hexdump context size —
                domain-validated later by ``ReportOptions`` (F-S-05).

        Returns:
            None

        Data Flow:
            - Refuse with one neutral status line when no project /
              variant set is active.
            - A retained snapshot from a DIFFERENT project directory is
              stale and treated as absent.
            - Without a usable snapshot, the same manifest-or-loaded-file
              guard as ``_trigger_execute_scope`` decides whether an
              active-scope run is even possible; the worker then executes
              with ``capture_mem_maps=True`` and generates in one pass.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``read_project_manifest``
                - ``_start_generate_report_worker``
            Used by:
                - ``on_report_viewer_screen_generate_requested``
        """
        project_dir = self._active_project_dir()
        variant_set = self._variant_set
        if project_dir is None or variant_set is None or not variant_set.variants:
            self.set_status("Report: no project variants - load a project first.")
            return
        last = self._last_execution
        if last is not None and last[0] != project_dir:
            self.logger.info(
                "Stale last-execution snapshot ignored (project changed)."
            )
            last = None
        fallback_batch: list[Path] = []
        if last is None:
            source_path = self._change_service.document.source_path
            fallback_batch = [source_path] if source_path is not None else []
            if not fallback_batch and read_project_manifest(project_dir) is None:
                self.set_status(
                    "Report: no manifest and no loaded change/check file - "
                    "nothing to report."
                )
                return
            self.set_status("Report: no prior execution - running active scope...")
        else:
            self.set_status("Report: generating from last execution...")
        self._start_generate_report_worker(
            project_dir, variant_set, context_bytes, last, fallback_batch
        )

    @work(thread=True, exclusive=True, group="generate_report")
    def _start_generate_report_worker(
        self,
        project_dir: Path,
        variant_set: ProjectVariantSet,
        context_bytes: int,
        last: Optional[tuple[Path, str, str, List[VariantExecutionResult]]],
        fallback_batch: list[Path],
    ) -> None:
        """
        Summary:
            Off-thread E8 generation worker: resolve the execution results
            (retained snapshot, or a fresh ``capture_mem_maps=True``
            active-scope run), build ``ReportOptions``, and call
            ``generate_project_report`` — every report-assembly decision
            lives in the service (LLR-008.5).

        Args:
            project_dir (Path): The active project directory.
            variant_set (ProjectVariantSet): The project's variant
                inventory at trigger time.
            context_bytes (int): The collected hexdump context size.
            last (Optional[tuple]): The validated retention snapshot
                ``(project_dir, scope, assignment_source, results)``, or
                ``None`` to execute the active scope first.
            fallback_batch (list[Path]): The manifest-absent default file
                list for the fresh-run path.

        Returns:
            None

        Data Flow:
            - The fresh-run results are LOCAL to this worker — they are
              never retained, so their mem_maps release on return.
            - A ``ValueError`` (the F-S-05 out-of-domain ``context_bytes``
              ERROR) and any service crash each surface as one status
              line; the retained snapshot is kept on failure so the
              operator can retry.
            - Success dispatches ``_finish_generate_report`` to the UI
              thread, which drops the retention and shows the path.

        Dependencies:
            Uses:
                - ``execute_project_variants`` / ``ReportOptions``
                - ``generate_project_report``
                - ``call_from_thread`` / ``_finish_generate_report``
            Used by:
                - ``_trigger_generate_report``
        """
        try:
            if last is None:
                scope = SCOPE_ACTIVE
                assignment_source = (
                    REPORT_SOURCE_MANIFEST
                    if read_project_manifest(project_dir) is not None
                    else REPORT_SOURCE_DEFAULT
                )
                results, _manifest_issues = execute_project_variants(
                    project_dir,
                    variant_set,
                    scope=scope,
                    fallback_batch=fallback_batch,
                    capture_mem_maps=True,
                    status_callback=lambda message: self.call_from_thread(
                        self.set_status, message
                    ),
                )
            else:
                _last_dir, scope, assignment_source, results = last
            options = ReportOptions(
                context_bytes=context_bytes,
                execution_mode=EXECUTION_SCOPE_TO_REPORT_MODE[scope],
                assignment_source=assignment_source,
            )
            report_path = generate_project_report(
                project_dir, results, options, variant_set=variant_set
            )
        except ValueError as exc:
            self.call_from_thread(self.set_status, f"Report rejected: {exc}")
            return
        except Exception as exc:
            self.logger.exception("Report generation failed: %s", exc)
            self.call_from_thread(
                self.set_status, f"Report failed: {type(exc).__name__}: {exc}"
            )
            return
        self.call_from_thread(self._finish_generate_report, report_path)

    def _finish_generate_report(self, report_path: Path) -> None:
        """
        Summary:
            UI-thread close of a successful generation: DROP the retained
            execution results (and their mem_maps — the E7 risk item),
            then show the written report's project-relative path in the
            status line (LLR-008.5; project-relative because the status
            log trims lines to 50 characters).

        Args:
            report_path (Path): The written report file.

        Returns:
            None

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``_start_generate_report_worker`` (via ``call_from_thread``)
        """
        self._last_execution = None
        self.logger.info("Report generated: %s", report_path)
        self.set_status(
            f"Report: {report_path.parent.name}/{report_path.name}"
        )

    def _compose_screen_diff(self) -> Container:
        """
        Summary:
            Build the Direction B A2B Diff rail screen (``#screen_diff``) as
            a title label plus the functional ``AbDiffPanel`` (HLR-005). The
            panel owns the inline image-pair selection, the comparison result
            columns and the report trigger; this builder constructs only the
            shell so the comparison/report logic stays in the panel + services
            (LLR-005.1), never in ``app.py``.

        Args:
            None

        Returns:
            Container: ``#screen_diff`` holding a title label and an
            ``AbDiffPanel``. Hidden at startup.

        Data Flow:
            - Shell composition only: the ``AbDiffPanel`` emits
              ``CompareRequested`` / ``ReportRequested`` messages that
              ``on_ab_diff_panel_*`` route through ``compare_service`` /
              ``diff_report_service``; this builder does no diff computation.

        Dependencies:
            Uses:
                - ``AbDiffPanel``
            Used by:
                - ``compose``
        """
        return Container(
            Label("A2B Diff", classes="db-screen-title"),
            AbDiffPanel(),
            id="screen_diff",
            classes="db-screen hidden",
        )

    def _prefill_diff_variants(self) -> None:
        """
        Summary:
            Prefill the A↔B Diff panel's variant ``Select`` dropdowns from the
            active project's ``ProjectVariantSet`` (LLR-005.1). Called when the
            diff screen activates; a no-project session yields an empty list
            (the panel keeps only its external-path option).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Map each ``VariantDescriptor`` to a ``(label, variant_id)`` pair
              and hand them to ``AbDiffPanel.set_variants``.

        Dependencies:
            Uses:
                - ``AbDiffPanel.set_variants``
            Used by:
                - ``action_show_screen`` (diff activation)
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        variants = (
            [(v.variant_id, v.variant_id) for v in self._variant_set.variants]
            if self._variant_set is not None
            else []
        )
        panel.set_variants(variants)

    def _diff_image_source(self, variant_id: Optional[str], raw_path: str) -> ImageSource:
        """
        Summary:
            Build one ``compare_service.ImageSource`` from the panel's raw
            selection — an in-project variant when ``variant_id`` is set, else
            an external path (LLR-005.1). The service does the resolution; this
            only packages the request.

        Args:
            variant_id (Optional[str]): The chosen project variant id, or
                ``None`` to use the external path.
            raw_path (str): The operator-typed external path.

        Returns:
            ImageSource: The packaged source for one comparison side.

        Dependencies:
            Used by:
                - ``on_ab_diff_panel_compare_requested``
        """
        if variant_id is not None:
            return ImageSource(kind=SOURCE_PROJECT_VARIANT, variant_id=variant_id)
        return ImageSource(kind=SOURCE_EXTERNAL, raw_path=raw_path)

    def on_ab_diff_panel_compare_requested(
        self, event: AbDiffPanel.CompareRequested
    ) -> None:
        """
        Summary:
            Route an A↔B compare request exclusively through
            ``compare_service.compare_images`` (LLR-005.1) and feed the result
            back to the panel; a refused comparison surfaces its diagnostic in
            the panel status and the screen keeps running (LLR-005.3). The app
            computes no run classification or coverage itself.

        Args:
            event (AbDiffPanel.CompareRequested): The raw image-pair selection
                the panel posted (variant id or external path per side).

        Returns:
            None

        Data Flow:
            - Package each side as an ``ImageSource`` (``_diff_image_source``).
            - Call ``compare_images`` with the active project's variant set and
              shared A2L/MAC context; never the TUI snapshot for the images.
            - Refused -> ``panel.set_status`` with the joined diagnostics.
            - Otherwise re-parse the two maps for display via the service-
              returned result is run-only; the panel renders runs + windows.

        Dependencies:
            Uses:
                - ``compare_images`` / ``_diff_image_source``
                - ``AbDiffPanel.render_comparison`` / ``set_status``
            Used by:
                - Textual message dispatch for ``AbDiffPanel``
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        loaded = self.current_file
        mac_records = loaded.mac_records if loaded is not None else None
        result = compare_images(
            self._diff_image_source(event.variant_a, event.path_a),
            self._diff_image_source(event.variant_b, event.path_b),
            variant_set=self._variant_set,
            base_dir=self.base_dir,
            a2l_data=self.current_a2l_data,
            mac_records=mac_records,
        )
        if result.refused:
            panel.set_status(
                "Compare refused: " + "; ".join(result.diagnostics),
                "sev-error",
            )
            return
        mem_map_a, mem_map_b = self._diff_load_maps(result)
        runs = [(run.start, run.end, run.kind) for run in result.runs]
        usage_a = result.notes.get("image_a")
        usage_b = result.notes.get("image_b")
        panel.render_comparison(
            runs,
            mem_map_a,
            mem_map_b,
            usage_a.summary if usage_a is not None else "none",
            usage_b.summary if usage_b is not None else "none",
        )
        panel.set_status(
            f"Compared {result.image_a.label} vs {result.image_b.label}: "
            f"{len(result.runs)} runs.",
            "sev-ok",
        )
        self._diff_last_result = result

    def _diff_load_maps(self, result) -> tuple[dict, dict]:
        """
        Summary:
            Re-load the two compared images' memory maps for the on-screen hex
            windows and the report (LLR-005.2 / LLR-005.4). The comparison
            service returns runs but not the maps; the panel and the report
            generator both need the raw bytes, so this re-parses by path
            through the existing headless loaders.

        Args:
            result (ComparisonResult): The completed comparison.

        Returns:
            tuple[dict, dict]: ``(mem_map_a, mem_map_b)``; an unreadable image
            yields an empty map (the hex window then shows nothing — non-fatal).

        Dependencies:
            Uses:
                - ``build_loaded_s19`` / ``build_loaded_hex``
            Used by:
                - ``on_ab_diff_panel_compare_requested``
        """
        def _load(image) -> dict:
            if not image.path:
                return {}
            path = Path(image.path)
            try:
                if path.suffix.lower() in (".hex", ".ihex"):
                    return build_loaded_hex(path, IntelHexFile(str(path)), None, None).mem_map
                return build_loaded_s19(path, S19File(str(path)), None, None).mem_map
            except Exception:  # noqa: BLE001 — display-side, non-fatal
                return {}

        return _load(result.image_a), _load(result.image_b)

    def on_ab_diff_panel_report_requested(
        self, event: AbDiffPanel.ReportRequested
    ) -> None:
        """
        Summary:
            Generate the diff report (Markdown + HTML) exclusively through
            ``diff_report_service`` (LLR-005.1) and surface the written
            path(s) — or the refusal diagnostic — in the panel status
            (LLR-005.4). The app computes no report content itself.

        Args:
            event (AbDiffPanel.ReportRequested): The operator-typed no-project
                destination directory (ignored when a project is active).

        Returns:
            None

        Data Flow:
            - Guard: no completed comparison -> one status line, no write.
            - Build the annotation inputs (enriched A2L tags + project MAC).
            - Call both generators with the project ``reports/`` dir, or the
              operator destination when no project is active (G-8).
            - Both written -> status with both paths; either refused -> the
              refusal diagnostic; the screen keeps running.

        Dependencies:
            Uses:
                - ``generate_diff_report`` / ``generate_diff_report_html``
                - ``AbDiffPanel.set_status``
            Used by:
                - Textual message dispatch for ``AbDiffPanel``
        """
        panel = self.query_one("#ab_diff_panel", AbDiffPanel)
        result = getattr(self, "_diff_last_result", None)
        if result is None or not panel.has_comparison():
            panel.set_status("No comparison yet — press Compare first.", "sev-warning")
            return
        project_dir = self._active_project_dir()
        dest_input = event.dest_input if project_dir is None else None
        loaded = self.current_file
        mac_records = loaded.mac_records if loaded is not None else None
        a2l_tags = self._compute_a2l_enriched_tags() or None
        kwargs = dict(
            mem_map_a=panel.mem_map_a,
            mem_map_b=panel.mem_map_b,
            project_dir=project_dir,
            dest_input=dest_input,
            a2l_records=a2l_tags,
            mac_records=mac_records,
        )
        md = generate_diff_report(result, **kwargs)
        if not md.written:
            panel.set_status(
                "Report refused: " + "; ".join(md.diagnostics), "sev-error"
            )
            return
        html = generate_diff_report_html(result, **kwargs)
        if not html.written:
            panel.set_status(
                "HTML report refused: " + "; ".join(html.diagnostics), "sev-error"
            )
            return
        panel.set_status(
            f"Diff report written: {md.path}  |  {html.path}", "sev-ok"
        )

    def _compose_screen_a2l(self) -> Container:
        """
        Summary:
            Build the Direction B A2L Explorer rail screen (``#screen_a2l``)
            as a two-pane horizontal layout — a ``1fr`` tags-table pane on
            the left and a fixed/proportional hex pane on the right
            (LLR-009.1).

        Args:
            None

        Returns:
            Container: ``#screen_a2l`` holding ``#a2l_panes`` (the two-pane
            ``Horizontal``). Hidden at startup.

        Data Flow:
            - Replaces the pre-batch ``#alt_layout`` 2x2 grid with a
              ``Horizontal`` of a left tags pane (``#a2l_tags_pane``,
              ``1fr``) and a right hex pane (``#a2l_hex_pane``, fixed-40 at
              >=120 cols / 35% under ``width-narrow`` — LLR-009.1).
            - Every widget subtree is reused verbatim so the A2L renderers
              keep working unchanged: the tags pane keeps ``#a2l_tags_list``,
              ``#a2l_tags_summary``, the filter row inputs/buttons, the
              ``#a2l_filter_menu`` overlay and its list; the hex pane keeps
              ``#alt_hex_view`` / ``#alt_hex_scroll`` / ``#alt_search_input`` /
              ``#alt_goto_input`` and the find/goto buttons. No
              renderer / paging / jump / filter logic is touched (LLR-009.2).

        Dependencies:
            Used by:
                - ``compose``
        """
        _tags_pane = Container(
            Label("A2L Tags", id="a2l_tags_title"),
            Container(
                Input(placeholder="Filter tags", id="a2l_tags_filter_input"),
                Button("Field: name", id="a2l_filter_field"),
                Button("All", id="a2l_filter_all"),
                Button("Invalid", id="a2l_filter_invalid"),
                Button("In-Memory", id="a2l_filter_inmem"),
                Input(placeholder="Find in tag table", id="a2l_tag_find_input"),
                Button("Find next", id="a2l_tag_find_next"),
                Button("Page Prev", id="a2l_page_prev_button"),
                Button("Page Next", id="a2l_page_next_button"),
                id="a2l_tags_filters",
            ),
            Container(
                ListView(id="a2l_filter_menu_list"),
                id="a2l_filter_menu",
                classes="hidden",
            ),
            DataTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row"),
            Label("", id="a2l_tags_summary"),
            id="a2l_tags_pane",
            classes="db-pane",
        )
        _hex_pane = Container(
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
            id="a2l_hex_pane",
            classes="db-pane",
        )
        _panes = Horizontal(
            _tags_pane,
            _hex_pane,
            id="a2l_panes",
        )
        return Container(
            _panes, id="screen_a2l", classes="db-screen hidden"
        )

    def _compose_screen_mac(self) -> Container:
        """
        Summary:
            Build the Direction B MAC View rail screen (``#screen_mac``) as a
            two-pane horizontal layout — a ``1fr`` records-table pane on the
            left and a fixed/proportional hex pane on the right (LLR-010.1).

        Args:
            None

        Returns:
            Container: ``#screen_mac`` holding ``#mac_panes`` (the two-pane
            ``Horizontal``). Hidden at startup.

        Data Flow:
            - Replaces the pre-batch ``#mac_layout`` 2x2 grid with a
              ``Horizontal`` of a left records pane (``#mac_records_pane``,
              ``1fr``) and a right hex pane (``#mac_hex_pane``, fixed-40 at
              >=120 cols / 35% under ``width-narrow`` — LLR-010.1).
            - Every widget subtree is reused verbatim so the MAC renderers
              keep working unchanged: the records pane keeps the page
              controls, ``#mac_records_list``, ``#mac_records_summary`` and
              the ``#mac_scroll`` wrapper; the hex pane keeps
              ``#mac_hex_view`` / ``#mac_hex_scroll`` / ``#mac_search_input`` /
              ``#mac_goto_input`` and the find/goto buttons. No renderer /
              paging / jump logic is touched, and the MAC-overlay hex
              highlight is preserved (LLR-010.2).

        Dependencies:
            Used by:
                - ``compose``
        """
        _records_pane = Container(
            Label("MAC File Content", id="mac_title"),
            Container(
                Button("Page Prev", id="mac_page_prev_button"),
                Button("Page Next", id="mac_page_next_button"),
                id="mac_page_controls",
            ),
            Container(
                DataTable(id="mac_records_list", zebra_stripes=True, cursor_type="row"),
                Label("", id="mac_records_summary"),
                id="mac_scroll",
            ),
            id="mac_records_pane",
            classes="db-pane",
        )
        _hex_pane = Container(
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
            id="mac_hex_pane",
            classes="db-pane",
        )
        _panes = Horizontal(
            _records_pane,
            _hex_pane,
            id="mac_panes",
        )
        return Container(
            _panes, id="screen_mac", classes="db-screen hidden"
        )

    def on_mount(self) -> None:
        self._setup_datatable_columns()
        # LLR-006.2: Comfortable is the default startup density.
        self.query_one("#workspace_body").add_class("density-comfortable")
        self.refresh_files()
        self._update_a2l_filter_menu()
        self._update_settings_menu()
        self.update_validation_issues_view()
        # LLR-002.3: show the no-file empty-state panels until a file loads.
        self._apply_empty_state()
        # Keep startup focus off the command-bar inputs so the unmodified
        # single-key bindings (rail digits 1-8, `/`, `g`, paging) fire
        # normally until the user explicitly focuses an input (LLR-004.5 —
        # suppression applies only *while* a command-bar input has focus).
        self._focus_activity_rail()
        if self.load_path:
            self.logger.info("Startup load requested: %s", self.load_path)
            self._load_path_from_user_input(self.load_path)

    def _focus_activity_rail(self) -> None:
        """Move keyboard focus to the active activity-rail item, if present."""
        try:
            rail = self.query_one(Rail)
        except Exception:
            return
        for item in rail.query(RailItem):
            if item.has_class("-active"):
                item.focus()
                return

    def _setup_datatable_columns(self) -> None:
        """
        Summary:
            Install the fixed column headers on the MAC, Issues, and A2L tag DataTables
            exactly once at mount so subsequent refreshes only call ``clear`` + ``add_rows``.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Query the three DataTables by id and add their static column labels.
            - Silently ignore duplicate-column errors so repeated mounts are harmless.

        Dependencies:
            Uses:
                - ``DataTable.add_columns``
            Used by:
                - ``on_mount``
        """
        try:
            mac_table = self.query_one("#mac_records_list", DataTable)
            if not mac_table.columns:
                mac_table.add_columns(
                    "Tag",
                    "Address",
                    "InA2L",
                    "InMem",
                    "Status",
                    "SourceLine",
                    "ParseErr",
                    "A2LMatch",
                )
        except Exception:
            self.logger.debug("MAC DataTable columns already initialized or missing.")
        try:
            issues_table = self.query_one("#validation_issues_list", DataTable)
            if not issues_table.columns:
                issues_table.add_columns(
                    "Severity",
                    "Code",
                    "Artifact",
                    "Symbol",
                    "Address",
                    "Line",
                    "Message",
                )
        except Exception:
            self.logger.debug("Issues DataTable columns already initialized or missing.")
        try:
            a2l_table = self.query_one("#a2l_tags_list", DataTable)
            if not a2l_table.columns:
                a2l_table.add_columns(
                    "Tag",
                    "Address",
                    "Length",
                    "Source",
                    "Raw",
                    "Physical",
                    "InMem",
                    "Region",
                    "Limits",
                    "Unit",
                    "Bits",
                    "Endian",
                    "Virt",
                    "Func",
                    "Access",
                    "Dtype",
                )
        except Exception:
            self.logger.debug("A2L DataTable columns already initialized or missing.")

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

    def action_select_variant(self) -> None:
        """
        Summary:
            Open the variant-selector modal for the active project (LLR-005.5).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bail with a status message when no project variant set exists.
            - Build ``(variant_id, display)`` options via
              ``_variant_display_options`` and locate the active index.
            - Push ``SelectVariantScreen`` with ``_handle_select_variant`` as
              the dismiss callback.

        Dependencies:
            Uses:
                - ``_variant_display_options``
                - ``SelectVariantScreen`` / ``push_screen``
            Used by:
                - ``v`` keybinding / command palette entry
        """
        variant_set = self._variant_set
        if variant_set is None or not variant_set.variants:
            self.set_status("No project variants to select.")
            self.logger.info("Select variant action triggered with no variant set.")
            return
        options = self._variant_display_options(variant_set)
        active_index = next(
            (
                index
                for index, variant in enumerate(variant_set.variants)
                if variant.variant_id == variant_set.active_id
            ),
            0,
        )
        self.logger.info(
            "Select variant action triggered. variants=%s active=%s",
            [variant.variant_id for variant in variant_set.variants],
            variant_set.active_id,
        )
        self.push_screen(
            SelectVariantScreen(variant_set.project_name, options, active_index),
            self._handle_select_variant,
        )

    def _handle_select_variant(self, variant_id: Optional[str]) -> None:
        """
        Summary:
            Activate the variant chosen in ``SelectVariantScreen`` through the
            existing threaded load pipeline (LLR-005.4).

        Args:
            variant_id (Optional[str]): Chosen variant id, or ``None`` on cancel.

        Returns:
            None

        Data Flow:
            - Resolve the descriptor in the current variant set (first match
              when duplicate ids exist — E6 decides duplicate-id policy).
            - Stamp ``_pending_variant_id`` on the main thread, then dispatch
              ``load_from_path`` so parsing runs on the load worker thread and
              ``_apply_prepared_load`` installs + stamps on the main thread.

        Dependencies:
            Uses:
                - ``load_from_path`` (existing load pipeline)
            Used by:
                - ``action_select_variant`` (modal dismiss callback)
        """
        if variant_id is None:
            self.logger.info("Select variant canceled.")
            return
        variant_set = self._variant_set
        if variant_set is None:
            return
        descriptor = next(
            (
                variant
                for variant in variant_set.variants
                if variant.variant_id == variant_id
            ),
            None,
        )
        if descriptor is None:
            self.set_status(f"Variant not found: {variant_id}")
            self.logger.warning("Variant not found in set: %s", variant_id)
            return
        if not descriptor.path.exists():
            self.set_status(f"Variant file missing: {descriptor.path.name}")
            self.logger.warning("Variant file missing on disk: %s", descriptor.path)
            return
        self.logger.info(
            "Activating variant '%s' via load pipeline: %s",
            variant_id,
            descriptor.path,
        )
        self._pending_variant_id = variant_id
        self.load_from_path(descriptor.path)

    def action_operations_view(self) -> None:
        """
        Summary:
            Open the operations modal for the current loaded file (batch-08
            HLR-004 / LLR-004.1) — key-bound (``x``) and palette-reachable.
            Orchestration only: enumeration comes from the registry, and the
            modal owns execution (through ``run_operation``) and result
            rendering; no operation or render logic lives here. Synchronous,
            no ``@work`` worker (LLR-004.4).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bail with one status line when no file is loaded (LLR-004.2
              guard) — no screen pushed, no service invoked.
            - Build ``(operation_id, title)`` options via
              ``list_operation_ids`` / ``get_operation`` (LLR-002.2) and
              push ``OperationsScreen`` with the current snapshot.

        Dependencies:
            Uses:
                - ``list_operation_ids`` / ``get_operation``
                - ``OperationsScreen`` / ``push_screen``
            Used by:
                - ``x`` keybinding / command palette entry
        """
        if self.current_file is None:
            self.set_status("Operations: no file loaded - load a file first.")
            self.logger.info("Operations view action triggered with no file loaded.")
            return
        options = [
            (operation_id, get_operation(operation_id).title)
            for operation_id in list_operation_ids()
        ]
        self.logger.info(
            "Operations view action. options=%s", [oid for oid, _ in options]
        )
        self.push_screen(OperationsScreen(options, self.current_file))

    def _variant_display_options(
        self, variant_set: ProjectVariantSet
    ) -> list[tuple[str, str]]:
        """
        Summary:
            Build ``(variant_id, display_label)`` pairs for the variant
            selector and the project context label.

        Args:
            variant_set (ProjectVariantSet): Variant inventory to label.

        Returns:
            list[tuple[str, str]]: One pair per variant in set order. The
            display label is the ``variant_id`` (filename stem), or the full
            filename when two variants share a stem (e.g. ``fw.s19`` +
            ``fw.hex`` — display-only disambiguation; the duplicate-id model
            itself is an E6 decision).

        Data Flow:
            - Count variant_id occurrences, then map each variant to its stem
              or, on duplicates, its ``path.name``.

        Dependencies:
            Used by:
                - ``action_select_variant``
                - ``update_project_labels``
        """
        counts = Counter(variant.variant_id for variant in variant_set.variants)
        return [
            (
                variant.variant_id,
                variant.path.name if counts[variant.variant_id] > 1 else variant.variant_id,
            )
            for variant in variant_set.variants
        ]

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

    #: Rail screen-key -> ``#workspace_body`` child container id (LLR-002.1).
    #: Ordered Workspace, A2L, MAC, Map, Issues, Patch, Diff, Bookmarks —
    #: the rail order of the keymap proposal (keys 1-8).
    SCREEN_CONTAINER_IDS = {
        "workspace": "screen_workspace",
        "a2l": "screen_a2l",
        "mac": "screen_mac",
        "map": "screen_map",
        "issues": "screen_issues",
        "patch": "screen_patch",
        "diff": "screen_diff",
        "bookmarks": "screen_bookmarks",
    }

    #: One extra command-palette command outside ``BINDINGS``: the viewer
    #: page-size settings menu lost its ``#view_bar`` trigger in increment 2
    #: (G-1) — it is resurfaced here so it stays keyboard-reachable (C-9).
    EXTRA_PALETTE_ENTRIES = (("Viewer settings", "open_settings_menu"),)

    def _build_palette_entries(self) -> tuple[PaletteEntry, ...]:
        """
        Summary:
            Build the command-palette command list 1:1 from ``BINDINGS`` so
            every key-bound action has exactly one palette entry that
            dispatches the same action id (LLR-003.2 parity by construction).

        Args:
            None

        Returns:
            tuple[PaletteEntry, ...]: One ``PaletteEntry`` per ``BINDINGS``
            action id (de-duplicated — the ``ctrl+l``/``l`` aliases share
            one action and one entry) plus the resurfaced "Viewer settings"
            command.

        Data Flow:
            - Walks ``BINDINGS``, keeping the first description seen for
              each distinct action id so aliased keys collapse to one entry.
            - Appends ``EXTRA_PALETTE_ENTRIES`` (the keyboard-reachable
              viewer settings command).

        Dependencies:
            Used by:
                - ``compose`` (the ``CommandBar`` palette)
        """
        entries: list[PaletteEntry] = []
        seen_actions: set[str] = set()
        for binding in self.BINDINGS:
            if isinstance(binding, Binding):
                action = binding.action
                description = binding.description
            else:
                action = binding[1]
                description = binding[2]
            if action in seen_actions:
                continue
            seen_actions.add(action)
            entries.append(PaletteEntry(description, action))
        for label, action in self.EXTRA_PALETTE_ENTRIES:
            entries.append(PaletteEntry(label, action))
        return tuple(entries)

    def action_show_screen(self, screen_key: str) -> None:
        """
        Summary:
            Activate a Direction B rail screen, showing its container and
            hiding the other seven (LLR-002.1).

        Args:
            screen_key (str): One of the keys of ``SCREEN_CONTAINER_IDS``
                (``workspace`` / ``a2l`` / ``mac`` / ``map`` / ``issues`` /
                ``patch`` / ``diff`` / ``bookmarks``).

        Returns:
            None

        Raises:
            None: An unknown ``screen_key`` is ignored (no screen change).

        Data Flow:
            - Reuses the existing ``.hidden``-class show/hide mechanism: the
              target ``#screen_*`` container loses ``.hidden`` and every
              other rail screen gains it. No ``push_screen`` is used, so the
              persistent command bar, rail and footer stay mounted.
            - Moves the activity rail's single active marker to the target
              screen via ``Rail.set_active`` (LLR-001.2), so the rail
              reflects the active screen for both the ``1``-``8`` key path
              and the rail-click path.

        Dependencies:
            Uses:
                - ``SCREEN_CONTAINER_IDS``
                - ``Rail.set_active``
            Used by:
                - The ``1``-``8`` key bindings
                - ``on_rail_selected`` (the activity rail click path)

        Example:
            >>> # bound to key "2"
            >>> app.action_show_screen("a2l")
        """
        if screen_key not in self.SCREEN_CONTAINER_IDS:
            return
        target_id = self.SCREEN_CONTAINER_IDS[screen_key]
        for container_id in self.SCREEN_CONTAINER_IDS.values():
            container = self.query_one(f"#{container_id}")
            if container_id == target_id:
                container.remove_class("hidden")
            else:
                container.add_class("hidden")
        self.query_one(Rail).set_active(screen_key)
        self._apply_empty_state()
        if screen_key == "diff":
            self._prefill_diff_variants()

    # Screens that own both real content and an `EmptyStatePanel`; the panel
    # is shown only while no file is loaded (LLR-002.3). Each tuple is the
    # screen container id and the id of its real-content child to hide.
    _EMPTY_STATE_SCREENS = (
        ("screen_workspace", "workspace_panes"),
        ("screen_issues", "issues_content"),
        ("screen_map", "map_content"),
    )

    def _apply_empty_state(self) -> None:
        """
        Summary:
            Toggle the no-file empty-state panels of the content-bearing rail
            screens — show the ``EmptyStatePanel`` and hide the real content
            while no file is loaded, and the reverse once a file is present
            (LLR-002.3).

        Args:
            None

        Returns:
            None

        Data Flow:
            - For each screen in ``_EMPTY_STATE_SCREENS``, resolve its real
              content child and its ``EmptyStatePanel``.
            - When ``current_file`` is unset, hide the content child and show
              the panel; otherwise show the content and hide the panel.
            - A missing widget tree (app not yet mounted) is tolerated — the
              helper is a no-op then, matching ``_focus_activity_rail``.

        Dependencies:
            Uses:
                - ``EmptyStatePanel``
            Used by:
                - ``action_show_screen``
                - ``_apply_prepared_load`` (post-load refresh)
        """
        no_file = self.current_file is None
        for screen_id, content_id in self._EMPTY_STATE_SCREENS:
            try:
                screen = self.query_one(f"#{screen_id}")
                content = screen.query_one(f"#{content_id}")
                panel = screen.query_one(EmptyStatePanel)
            except Exception:
                # App not mounted (e.g. headless unit tests of the load
                # pipeline) — empty-state has no tree to toggle yet.
                continue
            content.set_class(no_file, "hidden")
            panel.set_class(not no_file, "hidden")

    def on_rail_selected(self, event: Rail.Selected) -> None:
        """
        Summary:
            Route an activity-rail click to ``action_show_screen`` (LLR-002.1).

        Args:
            event (Rail.Selected): The rail-selection message carrying the
                clicked item's screen key.

        Returns:
            None

        Data Flow:
            - Delegates to ``action_show_screen`` so the rail-click path and
              the ``1``-``8`` key path share one routing implementation
              (including the active-marker move).

        Dependencies:
            Uses:
                - ``action_show_screen``
            Used by:
                - Textual message dispatch (``Rail.Selected`` bubbles up)
        """
        self.action_show_screen(event.key)

    def action_focus_palette(self) -> None:
        """Open and focus the command-bar palette (``Ctrl+K`` — LLR-004.3)."""
        self.query_one(CommandBar).open_palette()

    def action_focus_find(self) -> None:
        """Focus the command-bar find input (``/`` — LLR-004.1)."""
        self.query_one(CommandBar).focus_find()

    def action_focus_goto(self) -> None:
        """Focus the command-bar go-to-address input (``g`` — LLR-004.2)."""
        self.query_one(CommandBar).focus_goto()

    def action_open_settings_menu(self) -> None:
        """Open the viewer page-size settings menu (resurfaced via the palette)."""
        menu = self.query_one("#settings_menu")
        if "hidden" in menu.classes:
            self._update_settings_menu()
            menu.remove_class("hidden")

    def on_command_bar_find(self, event: CommandBar.Find) -> None:
        """
        Summary:
            Route a command-bar find submission to the existing validated
            search handler (LLR-004.6) without adding new decoding code.

        Args:
            event (CommandBar.Find): The find message carrying the raw
                typed query text.

        Returns:
            None

        Data Flow:
            - Copies the typed text into the existing ``#search_input``
              widget that ``_handle_search`` already reads, then calls
              ``_handle_search`` unchanged — so the search runs through the
              existing ``find_string_in_mem`` path and reports misses /
              malformed input via ``set_status`` exactly as today. No new
              search or string-decoding code is introduced (S-1).

        Dependencies:
            Uses:
                - ``_handle_search`` (which calls ``find_string_in_mem``)
            Used by:
                - Textual message dispatch (``CommandBar.Find`` bubbles up)
        """
        self.query_one("#search_input", Input).value = event.query
        self._handle_search()

    def on_command_bar_goto(self, event: CommandBar.Goto) -> None:
        """
        Summary:
            Route a command-bar go-to submission to the existing validated
            ``_handle_goto`` handler (LLR-004.2) without adding new
            address-parsing code.

        Args:
            event (CommandBar.Goto): The go-to message carrying the raw
                typed address text.

        Returns:
            None

        Data Flow:
            - Copies the typed text into the existing ``#goto_input`` widget
              that ``_handle_goto`` already reads off the widget tree, then
              calls ``_handle_goto`` unchanged — so the address is parsed
              and validated as today and malformed input is reported via
              ``set_status``. No new address-parsing code is introduced
              (S-1); ``_handle_goto``'s signature is unchanged.

        Dependencies:
            Uses:
                - ``_handle_goto``
            Used by:
                - Textual message dispatch (``CommandBar.Goto`` bubbles up)
        """
        self.query_one("#goto_input", Input).value = event.address_text
        self._handle_goto()

    async def on_command_bar_palette_action(
        self, event: CommandBar.PaletteAction
    ) -> None:
        """
        Summary:
            Dispatch a chosen command-palette command through the standard
            Textual action runner so it executes the *same* handler as the
            command's key binding (LLR-003.2).

        Args:
            event (CommandBar.PaletteAction): The palette message carrying
                the action id (e.g. ``"load_file"``, ``"show_screen('a2l')"``).

        Returns:
            None

        Data Flow:
            - Awaits ``run_action`` so the palette dispatch path is
              identical to a key binding firing the same action id.

        Dependencies:
            Uses:
                - ``run_action``
            Used by:
                - Textual message dispatch (``CommandBar.PaletteAction``)
        """
        await self.run_action(event.action)

    def _command_bar_input_focused(self) -> bool:
        """Return True while a command-bar ``Input`` holds keyboard focus."""
        focused = self.focused
        if not isinstance(focused, Input):
            return False
        try:
            command_bar = self.query_one(CommandBar)
        except Exception:
            return False
        return focused in command_bar.query(Input)

    #: Unmodified single-key bindings that, while a command-bar ``Input``
    #: holds focus, must be routed into the input as text rather than fired
    #: (keymap proposal §4 / LLR-004.5). Textual's focused ``Input`` already
    #: consumes most printable keys before they reach ``on_key``; in
    #: practice only ``period`` leaks (it reaches ``on_key`` with no
    #: ``character`` and would otherwise fire its paging binding), but the
    #: full keymap-§4 set is mapped so the suppression is explicit and
    #: version-robust. ``ctrl+*`` keys are absent — they stay live.
    _COMMAND_BAR_SUPPRESSED_KEYS = {
        "period": ".",
        "comma": ",",
        "plus": "+",
        "minus": "-",
        "g": "g",
        "q": "q",
        "slash": "/",
    }

    def on_key(self, event: events.Key) -> None:
        """
        Summary:
            Suppress unmodified single-key bindings while a command-bar
            ``Input`` holds focus, routing the keystroke into the input as
            text instead (LLR-004.5 / keymap proposal §4).

        Args:
            event (events.Key): The key event delivered to the app after
                the focused widget declined to consume it.

        Returns:
            None

        Data Flow:
            - This handler only sees keys the focused ``Input`` did not
              already consume (Textual delivers an unhandled key up the
              focus chain). The focused ``Input`` already consumes the
              printable single keys; this handler catches the residual
              leaked single-key bindings (notably ``.``) that would
              otherwise fire a paging / navigation action.
            - While a command-bar input is focused and the key is one of
              ``_COMMAND_BAR_SUPPRESSED_KEYS``, its character is inserted
              into the focused input and the event is stopped, so the
              binding action does not fire. Modified-key bindings
              (``ctrl+*``) are not in the suppressed set and stay live.

        Dependencies:
            Uses:
                - ``_command_bar_input_focused``
            Used by:
                - Textual key-event dispatch
        """
        if event.key not in self._COMMAND_BAR_SUPPRESSED_KEYS:
            return
        if not self._command_bar_input_focused():
            return
        focused = self.focused
        if isinstance(focused, Input):
            focused.insert_text_at_cursor(self._COMMAND_BAR_SUPPRESSED_KEYS[event.key])
        event.stop()
        event.prevent_default()

    def action_view_main(self) -> None:
        """Legacy alias: activate the Workspace rail screen (superseded by key ``1``)."""
        self.action_show_screen("workspace")

    def action_view_alt(self) -> None:
        """Legacy alias: activate the A2L Explorer rail screen (superseded by key ``2``)."""
        self.action_show_screen("a2l")

    def action_view_mac(self) -> None:
        """Legacy alias: activate the MAC View rail screen (superseded by key ``3``)."""
        self.action_show_screen("mac")

    def action_cycle_density(self) -> None:
        """
        Summary:
            Cycle the workspace layout density between compact and
            comfortable (LLR-006.1), toggling a density CSS class on the
            ``#workspace_body`` root.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reads the current ``density-compact`` / ``density-comfortable``
              class on ``#workspace_body``, swaps to the other, and reports
              the new mode via ``set_status``.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - The ``ctrl+d`` key binding

        Example:
            >>> app.action_cycle_density()  # comfortable -> compact
        """
        body = self.query_one("#workspace_body")
        if body.has_class("density-compact"):
            body.remove_class("density-compact")
            body.add_class("density-comfortable")
            self.set_status("Density: comfortable")
        else:
            body.remove_class("density-comfortable")
            body.add_class("density-compact")
            self.set_status("Density: compact")

    def _apply_width_regime(self, width: int) -> None:
        """
        Summary:
            Toggle the ``width-narrow`` class for the two-regime width
            layout (LLR-007.1): narrow below the 120-column breakpoint,
            wide at or above it. The class is set on both ``#workspace_shell``
            and ``#workspace_body``.

        Args:
            width (int): Current terminal width in columns.

        Returns:
            None

        Data Flow:
            - At ``width < 120`` the ``width-narrow`` class is set so the
              proportional-pane and collapsed-rail rules apply; at
              ``width >= 120`` it is cleared so the fixed-width rules apply.
            - The class is set on ``#workspace_shell`` so the collapsed-rail
              rule can reach ``#rail_slot`` (a sibling of ``#workspace_body``,
              not a descendant), and also on ``#workspace_body`` so the
              per-screen proportional-pane rules keep their existing selector.

        Dependencies:
            Used by:
                - ``on_resize``
        """
        narrow = width < 120
        for widget_id in ("#workspace_shell", "#workspace_body"):
            widget = self.query_one(widget_id)
            if narrow:
                widget.add_class("width-narrow")
            else:
                widget.remove_class("width-narrow")

    def on_resize(self, event: events.Resize) -> None:
        """Update the two-regime width layout class on terminal resize."""
        self._apply_width_regime(event.size.width)

    def action_page_next_context(self) -> None:
        """
        Summary:
            Route context page-next to the active non-main viewer table.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Inspect current visible layout.
            - Forward to A2L or MAC page-next action.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``action_a2l_tags_page_next``
                - ``action_mac_records_page_next``
        """
        active = self._active_view_name()
        if active == "alt":
            self.action_a2l_tags_page_next()
        elif active == "mac":
            self.action_mac_records_page_next()

    def action_page_prev_context(self) -> None:
        """
        Summary:
            Route context page-prev to the active non-main viewer table.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Inspect current visible layout.
            - Forward to A2L or MAC page-prev action.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``action_a2l_tags_page_prev``
                - ``action_mac_records_page_prev``
        """
        active = self._active_view_name()
        if active == "alt":
            self.action_a2l_tags_page_prev()
        elif active == "mac":
            self.action_mac_records_page_prev()

    def action_hex_page_next(self) -> None:
        """
        Summary:
            Advance the main hex viewer window by one configured page of rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Guard on active layout and loaded row-base data.
            - Move ``_hex_window_start`` forward by ``hex_rows_page_size``.
            - Re-render main hex panel.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``update_hex_view``
        """
        if self._active_view_name() != "main":
            return
        if not self.current_file or not self.current_file.row_bases:
            return
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        total = len(self.current_file.row_bases)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._hex_window_start = min(max_start, self._hex_window_start + page_size)
        self.last_search_address = None
        self._goto_focus_address = None
        self.update_hex_view()

    def action_hex_page_prev(self) -> None:
        """
        Summary:
            Move the main hex viewer window back by one configured page of rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Guard on active layout and loaded row-base data.
            - Move ``_hex_window_start`` backward by ``hex_rows_page_size``.
            - Re-render main hex panel.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``update_hex_view``
        """
        if self._active_view_name() != "main":
            return
        if not self.current_file or not self.current_file.row_bases:
            return
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        self._hex_window_start = max(0, self._hex_window_start - page_size)
        self.last_search_address = None
        self._goto_focus_address = None
        self.update_hex_view()

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
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._a2l_window_start = min(max_start, self._a2l_window_start + page_size)
        self._alt_goto_focus_address = None
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
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        self._a2l_window_start = max(0, self._a2l_window_start - page_size)
        self._alt_goto_focus_address = None
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
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._mac_window_start = min(max_start, self._mac_window_start + page_size)
        self._mac_goto_focus_address = None
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
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        self._mac_window_start = max(0, self._mac_window_start - page_size)
        self._mac_goto_focus_address = None
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
        # Multi-variant model (E5b, US-005): saving an S19/HEX into a project
        # that already holds primaries is a legitimate variant addition — the
        # pre-batch cross-suffix rejection is retired. Filename collisions are
        # deduplicated by ``copy_into_workarea`` (`_<N>` suffix); the single-MAC
        # and single-A2L guards below are preserved (LLR-005.1).
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
        saved_variant_id: Optional[str] = None
        saved_primary_name: Optional[str] = None
        try:
            if self.current_file:
                saved = copy_into_workarea(self.current_file.path, project_dir)
                self.logger.info("Project saved. name=%s file=%s", cleaned, saved)
                if saved.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS:
                    saved_primary_name = saved.name
                if self.current_file.mac_path and self.current_file.mac_path != self.current_file.path:
                    saved_mac = copy_into_workarea(self.current_file.mac_path, project_dir)
                    self.logger.info("Project saved MAC. name=%s file=%s", cleaned, saved_mac)
            if self.current_a2l_path:
                saved_a2l = copy_into_workarea(self.current_a2l_path, project_dir)
                self.logger.info("Project saved A2L. name=%s file=%s", cleaned, saved_a2l)
        except WorkareaContainmentError as exc:
            self.set_status(f"Cannot save project: {exc}")
            self.logger.warning("Project save rejected by workarea guard: %s", exc)
            return
        self.current_project = cleaned
        self.current_project_dir = project_dir
        # Rebuild the variant inventory from the on-disk project so the saved
        # image becomes the active variant (multi-variant model, E5b). The id
        # is resolved AFTER the build by filename match because a stem
        # collision makes the id the full filename (E6 duplicate-id rule).
        saved_data_files, _saved_a2l_files, variant_error = validate_project_files(project_dir)
        if variant_error is None:
            self._variant_set = build_variant_set(cleaned, saved_data_files)
            if saved_primary_name:
                saved_variant_id = next(
                    (
                        variant.variant_id
                        for variant in self._variant_set.variants
                        if variant.path.name == saved_primary_name
                    ),
                    None,
                )
            if saved_variant_id:
                self._variant_set.active_id = saved_variant_id
                if self.current_file:
                    self.current_file.variant_id = saved_variant_id
        else:
            self._variant_set = None
            self.logger.warning(
                "Variant set not built after save: %s", variant_error
            )
        if saved_variant_id:
            self.set_status(
                f"Saved project to {project_dir} (variant '{saved_variant_id}')"
            )
        else:
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
        # Multi-variant model (LLR-005.6, completed at E6): the manifest's
        # recorded ``active_variant`` wins when present AND valid; otherwise
        # the FIRST variant in the deterministic ``(name.lower(), name)``
        # order of ``build_variant_set`` (with a status warning when the
        # manifest names an unknown variant).
        variant_set = build_variant_set(name, data_files)
        manifest = read_project_manifest(project_dir)
        if manifest is not None and manifest.active_variant is not None:
            known_ids = {variant.variant_id for variant in variant_set.variants}
            if manifest.active_variant in known_ids:
                variant_set.active_id = manifest.active_variant
            else:
                self.set_status(
                    f"Manifest active_variant '{manifest.active_variant}' "
                    "not found - activating the first variant."
                )
                self.logger.warning(
                    "Manifest active_variant unknown: %s (known: %s)",
                    manifest.active_variant,
                    sorted(known_ids),
                )
        active_variant = next(
            (
                variant
                for variant in variant_set.variants
                if variant.variant_id == variant_set.active_id
            ),
            None,
        )
        primary_file = active_variant.path if active_variant else None
        mac_file = next((item for item in data_files if item.suffix.lower() in MAC_EXTENSIONS), None)
        selected_file = primary_file or mac_file
        if selected_file is None:
            self.set_status(f"No supported files in project: {name}")
            self.logger.warning("No loadable data file in project: %s", name)
            return
        self.current_project = name
        self.current_project_dir = project_dir.resolve()
        self._variant_set = variant_set
        self._pending_variant_id = (
            active_variant.variant_id if active_variant else None
        )
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
        """
        Summary:
            Copy the freshly loaded data file into the active project —
            appending S19/HEX loads as new project variants (E5a finding 2:
            the pre-batch silent skip is retired).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bail when no file or no active project directory exists.
            - Primary (S19/HEX) loads: skip when ``current_file.variant_id``
              already names a variant in ``_variant_set`` (a variant
              activation reload); otherwise copy the file in, rebuild the
              variant set with the new file active, stamp
              ``current_file.variant_id``, and report the appended variant in
              the status line.
            - MAC loads keep the pre-batch single-MAC sync rules.

        Dependencies:
            Uses:
                - ``validate_project_files`` / ``build_variant_set`` /
                  ``copy_into_workarea``
                - ``update_project_labels`` / ``set_status``
            Used by:
                - ``_start_load_worker`` (via ``call_from_thread``, after
                  ``_apply_prepared_load`` installed the load)
        """
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
        try:
            if self.current_file.path.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS:
                known_variant_ids = (
                    {variant.variant_id for variant in self._variant_set.variants}
                    if self._variant_set is not None
                    else set()
                )
                if (
                    self.current_file.variant_id is not None
                    and self.current_file.variant_id in known_variant_ids
                ):
                    # Variant activation reload — the image already belongs to
                    # the project; nothing to append.
                    self.logger.info(
                        "Sync skipped: variant '%s' already in project %s",
                        self.current_file.variant_id,
                        project_dir,
                    )
                else:
                    saved = copy_into_workarea(self.current_file.path, project_dir)
                    project_name = self.current_project or project_dir.name
                    appended_id = saved.stem
                    synced_files, _synced_a2l, sync_error = validate_project_files(project_dir)
                    if sync_error is None:
                        # Resolve the id AFTER the build by filename match —
                        # a stem collision makes the id the full filename
                        # (E6 duplicate-id rule).
                        self._variant_set = build_variant_set(project_name, synced_files)
                        appended_id = next(
                            (
                                variant.variant_id
                                for variant in self._variant_set.variants
                                if variant.path.name == saved.name
                            ),
                            saved.stem,
                        )
                        self._variant_set.active_id = appended_id
                        self.current_file.variant_id = appended_id
                        self.update_project_labels()
                    else:
                        self.logger.warning(
                            "Variant set not rebuilt during sync: %s", sync_error
                        )
                    self.set_status(
                        f"Added variant '{appended_id}' to project '{project_name}'"
                    )
                    self.logger.info(
                        "Appended variant '%s' into project: %s", appended_id, project_dir
                    )
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
        except WorkareaContainmentError as exc:
            self.set_status(f"Project sync rejected: {exc}")
            self.logger.warning("Project sync rejected by workarea guard: %s", exc)

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
        try:
            copy_into_workarea(self.current_a2l_path, project_dir)
            self.logger.info("Synced A2L file into project: %s", project_dir)
        except WorkareaContainmentError as exc:
            self.set_status(f"A2L sync rejected: {exc}")
            self.logger.warning("A2L sync rejected by workarea guard: %s", exc)

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
        """
        Summary:
            Handle the LoadFileScreen result callback and defer the actual load work
            so Textual can process the screen-pop message before any blocking code runs.

        Args:
            path (Optional[Path]): Path entered in the dialog, or ``None`` on cancel.

        Returns:
            None

        Data Flow:
            - Return immediately on cancel.
            - Log a ``modal_dismiss_scheduled`` phase boundary and flush the handler.
            - Schedule ``_load_path_from_user_input`` via ``call_after_refresh`` so the
              modal-pop message processes before the load starts on the main thread.

        Dependencies:
            Uses:
                - ``_load_path_from_user_input``
                - ``_flush_logger``
                - ``call_after_refresh``
            Used by:
                - ``action_load_file`` (LoadFileScreen result callback)
        """
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
        self.logger.info("Load phase boundary: modal_dismiss_scheduled path=%s", path)
        self._flush_logger()
        # Defer the load so Textual's pop_screen message queued by Screen.dismiss()
        # is processed first; otherwise the modal stays visible for the duration of
        # the copy/parse/install pipeline because dismiss() invokes this callback
        # synchronously before scheduling the pop.
        self.call_after_refresh(self._load_path_from_user_input, path)
        self.logger.info("DBG H4 load dialog callback exit (deferred): path=%s", path)
        # region agent log
        self._debug_log(
            run_id="initial",
            hypothesis_id="H4",
            location="s19_app/tui/app.py:_handle_load_dialog",
            message="Scheduled deferred load after modal pop",
            data={"path": str(path)},
        )
        # endregion

    def load_from_path(self, path: Path) -> None:
        """
        Summary:
            Resolve a user-supplied path, copy the source into the workarea temp folder, and
            launch an off-thread worker that parses the file and refreshes the UI.

        Args:
            path (Path): Path entered in the load dialog (relative or absolute).

        Returns:
            None

        Data Flow:
            - Validate/resolve the path and check the extension is supported.
            - Copy into ``workarea/temp`` while keeping the UI responsive.
            - Dispatch ``_start_load_worker`` so the heavy parse runs off the event loop.

        Dependencies:
            Uses:
                - ``resolve_input_path``
                - ``copy_into_workarea``
                - ``refresh_files`` / ``set_progress``
                - ``_start_load_worker``
            Used by:
                - ``_load_path_from_user_input`` (load dialog + startup path)
        """
        self.logger.info("Load phase boundary: dialog_callback_entry path=%s", path)
        self._flush_logger()
        normalized = resolve_input_path(path, self.base_dir)
        if not normalized:
            self._pending_variant_id = None
            self.set_status(f"File not found: {path}")
            self.logger.warning("File not found: %s", path)
            return
        if normalized.suffix.lower() not in SUPPORTED_EXTENSIONS:
            self._pending_variant_id = None
            self.set_status(f"Unsupported file type: {normalized.suffix}")
            self.logger.warning("Unsupported file type: %s", normalized.suffix)
            return
        temp_dir = self.workarea / WORKAREA_TEMP
        self.set_progress(10, "Copying into workarea temp...")
        self.logger.info("Load phase boundary: copy_started path=%s", normalized)
        self._flush_logger()
        copy_started = time.perf_counter()
        try:
            copied = copy_into_workarea(normalized, temp_dir)
        except WorkareaContainmentError as exc:
            self._pending_variant_id = None
            self.set_progress(0, "")
            self.set_status(f"Cannot load file: {exc}")
            self.logger.warning("Load rejected by workarea guard: %s", exc)
            return
        copy_elapsed = time.perf_counter() - copy_started
        self.logger.info(
            "Load phase boundary: copy_done path=%s elapsed=%.3fs",
            copied.name,
            copy_elapsed,
        )
        self._flush_logger()
        self.set_progress(50, f"Parsing {copied.name}...")
        # Kick the worker off before anything else so the modal-dismiss callback yields
        # control back to the event loop promptly. Workarea refresh + diagnostic log are
        # dispatched via ``call_later`` so they run on the next idle frame.
        self._start_load_worker(copied)
        copied_size = copied.stat().st_size

        def _post_worker_launch() -> None:
            self.refresh_files()
            self.logger.info(
                "File copied to temp: path=%s size_bytes=%d copy_seconds=%.3f",
                copied,
                copied_size,
                copy_elapsed,
            )
            self.logger.info("Load phase boundary: worker_spawned path=%s", copied.name)
            self._flush_logger()

        self.call_later(_post_worker_launch)

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
        try:
            copied = copy_into_workarea(normalized, temp_dir)
        except WorkareaContainmentError as exc:
            self.set_progress(0, "")
            self.set_status(f"Cannot load A2L: {exc}")
            self.logger.warning("A2L load rejected by workarea guard: %s", exc)
            return
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
        if event.list_view.id == "a2l_filter_menu_list":
            if event.item is None:
                return
            field = getattr(event.item, "data", None)
            if field:
                self._set_a2l_filter_field(field)
            return
        if event.list_view.id == "settings_menu_list":
            if event.item is None:
                return
            payload = getattr(event.item, "data", None)
            if (
                isinstance(payload, tuple)
                and len(payload) == 2
                and isinstance(payload[0], str)
                and isinstance(payload[1], int)
            ):
                self._apply_viewer_setting(payload[0], payload[1])
            return
        # ``mac_records_list``, ``validation_issues_list``, and ``a2l_tags_list`` are
        # now ``DataTable`` widgets; selection for those IDs arrives via
        # ``on_data_table_row_selected`` instead of this ListView handler.

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """
        Summary:
            Dispatch a ``DataTable.RowSelected`` event to the correct jump helper by
            looking at the selected table's id and the encoded row_key.

        Args:
            event (DataTable.RowSelected): Event payload with ``data_table`` and
                ``row_key`` attributes.

        Returns:
            None

        Data Flow:
            - Pull the table id from ``event.data_table`` and the row_key value.
            - MAC rows -> ``_jump_to_mac_address`` via the ``_mac_row_key_to_address`` map.
            - Issue rows -> ``_jump_to_validation_issue_by_index`` via the filtered list.
            - A2L rows -> ``_jump_to_tag_by_data`` via the ``_a2l_row_key_to_tag`` map.

        Dependencies:
            Uses:
                - ``_jump_to_mac_address``
                - ``_jump_to_validation_issue_by_index``
                - ``_jump_to_tag_by_data``
            Used by:
                - Textual event dispatch for ``DataTable.RowSelected``
        """
        table = getattr(event, "data_table", None)
        table_id = getattr(table, "id", None) if table is not None else None
        row_key = getattr(event, "row_key", None)
        key_value = getattr(row_key, "value", row_key)
        if not isinstance(key_value, str):
            return
        if table_id == "mac_records_list":
            address = self._mac_row_key_to_address.get(key_value)
            if isinstance(address, int):
                self._jump_to_mac_address(address)
            return
        if table_id == "validation_issues_list":
            absolute_index = self._issue_row_key_to_index.get(key_value)
            if isinstance(absolute_index, int):
                self._jump_to_validation_issue_by_index(absolute_index)
            return
        if table_id == "a2l_tags_list":
            tag = self._a2l_row_key_to_tag.get(key_value)
            if isinstance(tag, dict):
                self._jump_to_tag_by_data(tag)
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
            Legacy ListView adapter that unpacks ``item.data`` into the shared
            ``_jump_to_tag_by_data`` helper so both DataTable and ListView paths
            share one implementation.

        Args:
            item (ListItem): A2L tags table row with ``item.data`` holding ``tag``.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_jump_to_tag_by_data``
        """
        tag_info = getattr(item, "data", None)
        if not isinstance(tag_info, dict):
            return
        tag = tag_info.get("tag")
        if isinstance(tag, dict):
            self._jump_to_tag_by_data(tag)

    def _jump_to_tag_by_data(self, tag: dict) -> None:
        """
        Summary:
            Focus the alt hex panel on an A2L tag's address with a byte-range highlight.

        Args:
            tag (dict): Enriched A2L tag dict carrying ``address`` and optionally ``length``.

        Returns:
            None

        Data Flow:
            - Return early when no integer address is present.
            - Store ``_a2l_tag_hex_highlight`` so ``update_alt_hex_view`` can paint a span.
            - Re-render alt hex centered on the tag address.

        Dependencies:
            Uses:
                - ``_a2l_tag_byte_length_for_hex_highlight``
                - ``update_alt_hex_view``
                - ``set_status``
            Used by:
                - ``on_data_table_row_selected`` for the A2L DataTable
                - ``_jump_to_tag`` (legacy ListView adapter)
        """
        addr = tag.get("address") if isinstance(tag, dict) else None
        if not isinstance(addr, int):
            return
        span = self._a2l_tag_byte_length_for_hex_highlight(tag if isinstance(tag, dict) else {})
        self._a2l_tag_hex_highlight = (addr, span)
        self.last_search_address = None
        self._alt_goto_focus_address = None
        self.update_alt_hex_view(addr, near_top=True, reset_scroll=True)
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
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        self._a2l_window_start = (absolute_index // page_size) * page_size
        self.update_a2l_tags_view(tags)
        try:
            a2l_table = self.query_one("#a2l_tags_list", DataTable)
            row_offset = absolute_index - self._a2l_window_start
            if 0 <= row_offset < a2l_table.row_count:
                a2l_table.move_cursor(row=row_offset)
        except Exception:
            # Widget may not be fully mounted in test harnesses; focus is best-effort.
            pass
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
                _safe(tag.get("raw_value")),
                _safe(tag.get("physical_value")),
                _a2l_tag_in_memory_display(tag),
                _safe(tag.get("lower_limit")),
                _safe(tag.get("upper_limit")),
                _a2l_tag_unit_display(tag),
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
                self.last_search_address = None
                self._alt_goto_focus_address = None
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
        """Legacy ListView adapter that forwards to ``_jump_to_mac_address``."""
        info = getattr(item, "data", None)
        if not info:
            return
        addr = info.get("address")
        if isinstance(addr, int):
            self._jump_to_mac_address(addr)

    def _jump_to_mac_address(self, address: int) -> None:
        """
        Summary:
            Focus the MAC hex panel on a MAC row's address and surface a status note.

        Args:
            address (int): Absolute memory address for the selected MAC record.

        Returns:
            None

        Dependencies:
            Uses:
                - ``update_mac_hex_view``
                - ``set_status``
            Used by:
                - ``on_data_table_row_selected`` for the MAC DataTable
                - ``_jump_to_mac_record`` (legacy ListView adapter)
        """
        self.last_search_address = None
        self._mac_goto_focus_address = None
        self.update_mac_hex_view(address, near_top=True, reset_scroll=True)
        self.set_status(f"MAC tag at 0x{address:08X}")

    def _jump_to_validation_issue(self, item: ListItem) -> None:
        """Legacy ListView adapter that forwards to ``_jump_to_validation_issue_object``."""
        info = getattr(item, "data", None)
        if not isinstance(info, dict):
            return
        issue_stub = ValidationIssue(
            code=str(info.get("code") or ""),
            severity=ValidationSeverity.INFO,
            artifact="",
            message="",
            symbol=str(info.get("symbol") or "") or None,
            address=info.get("address") if isinstance(info.get("address"), int) else None,
            line_number=info.get("line_number") if isinstance(info.get("line_number"), int) else None,
        )
        self._jump_to_validation_issue_object(issue_stub)

    def _jump_to_validation_issue_by_index(self, absolute_index: int) -> None:
        """
        Summary:
            Look up a validation issue by its absolute index in the current filtered
            list and jump to its hex/tag context.

        Args:
            absolute_index (int): Index into ``_filtered_validation_issues()`` result.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_filtered_validation_issues``
                - ``_jump_to_validation_issue_object``
            Used by:
                - ``on_data_table_row_selected`` for the Issues DataTable
        """
        filtered = self._filtered_validation_issues()
        if 0 <= absolute_index < len(filtered):
            self._jump_to_validation_issue_object(filtered[absolute_index])

    def _jump_to_validation_issue_object(self, issue: ValidationIssue) -> None:
        """
        Summary:
            Focus related hex/tag context for a selected validation issue.

        Args:
            issue (ValidationIssue): Issue whose address (if any) or symbol drives the jump.

        Returns:
            None

        Data Flow:
            - Prefer the integer address field when present: refresh all three hex views.
            - Otherwise fall back to the symbol and look it up in the filtered A2L tags.

        Dependencies:
            Uses:
                - ``update_hex_view`` / ``update_alt_hex_view`` / ``update_mac_hex_view``
                - ``_focus_a2l_tag_absolute_index``
                - ``set_status``
            Used by:
                - ``_jump_to_validation_issue_by_index``
                - ``_jump_to_validation_issue`` (legacy adapter)
        """
        address = issue.address
        if isinstance(address, int) and self.current_file:
            self.update_hex_view(address)
            self.update_alt_hex_view(address)
            self.update_mac_hex_view(address)
            self.set_status(f"Issue at 0x{address:08X}: {issue.code or 'validation'}")
            return
        symbol = (issue.symbol or "").strip()
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
        """
        Summary:
            Render a paged window of validation issues into the Issues ``DataTable``
            and push aggregate totals into the adjacent summary ``Label``.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Resolve the filtered list via ``_filtered_validation_issues``.
            - Short-circuit with a summary-only message when there are no issues.
            - Compute aggregate counts (errors/warnings/info) and a page-number line.
            - Use worker-precomputed cell rows/styles when the filter is ``all``, else
              format the filtered subset on the fly (cheap, already filtered down).
            - Insert the page rows via ``DataTable.add_row`` with row_keys of the form
              ``issue:<absolute_index>`` so ``on_data_table_row_selected`` can jump.

        Dependencies:
            Uses:
                - ``_filtered_validation_issues``
                - ``_clamp_viewer_page_size`` / ``_get_window_bounds``
                - ``precompute_issue_datatable_payload`` (fallback)
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
                - ``update_mac_view`` (when MAC/validation input changes)
                - issue filter buttons and paging actions
        """
        populate_started = time.perf_counter()
        issue_table = self.query_one("#validation_issues_list", DataTable)
        summary_label = self.query_one("#validation_issues_summary", Label)
        self._issue_row_key_to_index = {}
        issue_table.clear(columns=False)
        filtered = self._filtered_validation_issues()
        if not filtered:
            summary_label.update("No validation issues.")
            self.logger.info(
                "Load phase boundary: populate_issues_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        error_count = sum(1 for item in self._validation_issues if item.severity == ValidationSeverity.ERROR)
        warning_count = sum(1 for item in self._validation_issues if item.severity == ValidationSeverity.WARNING)
        info_count = sum(1 for item in self._validation_issues if item.severity == ValidationSeverity.INFO)
        total = len(filtered)
        page_size = self._clamp_viewer_page_size(self.validation_issues_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size) if total else 0
        self._validation_issues_window_start = max(0, min(self._validation_issues_window_start, max_start))
        start, end = self._get_window_bounds(total, self._validation_issues_window_start, page_size)
        self._validation_issues_window_start = start
        page_num = start // page_size + 1
        total_pages = max(1, (total + page_size - 1) // page_size)
        summary_text = " | ".join(
            [
                f"total={len(self._validation_issues)}",
                f"errors={error_count}",
                f"warnings={warning_count}",
                f"info={info_count}",
                f"filter={self.validation_issue_filter_mode}",
                f"page {page_num}/{total_pages} rows {start + 1}-{end}/{total}",
            ]
        )
        summary_label.update(summary_text)
        use_precomputed = (
            self.validation_issue_filter_mode == "all"
            and len(self._validation_issue_cell_rows) == len(self._validation_issues)
        )
        if use_precomputed:
            cell_rows = self._validation_issue_cell_rows
            styles = self._validation_issue_cell_styles
            index_base = start
            visible_rows = cell_rows[start:end]
            visible_styles = styles[start:end]
            visible_issues = filtered[start:end]
        else:
            visible_issues = filtered[start:end]
            visible_rows, visible_styles = precompute_issue_datatable_payload(visible_issues)
            index_base = start
        self._populate_issues_datatable(
            issue_table, visible_rows, visible_styles, visible_issues, index_base
        )
        self.logger.info(
            "Load phase boundary: populate_issues_table_done rows=%d total=%d elapsed=%.3f",
            len(visible_rows),
            total,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _populate_issues_datatable(
        self,
        issue_table: "DataTable",
        visible_rows: list[tuple[str, ...]],
        visible_styles: list[str],
        visible_issues: list[ValidationIssue],
        index_base: int,
    ) -> None:
        """
        Summary:
            Insert a page of issue rows into the Issues ``DataTable`` using Rich
            ``Text`` cells styled by severity, and record the row_key -> filtered
            index map that ``on_data_table_row_selected`` consumes.

        Args:
            issue_table (DataTable): Target issues table.
            visible_rows (list[tuple[str, ...]]): Pre-formatted 7-tuple cells.
            visible_styles (list[str]): Per-row Rich style strings.
            visible_issues (list[ValidationIssue]): Parallel issue objects (for jump).
            index_base (int): Absolute index of the first visible row for row_keys.

        Returns:
            None

        Data Flow:
            - Build styled ``Text`` cells so severity color applies to every column.
            - Emit a unique row_key per row (``issue:<index>``).
            - Call ``DataTable.add_row`` per row; O(1) dict insert per row (no mount).
            - Remember the filtered-list index on ``_issue_row_key_to_index``.

        Dependencies:
            Used by:
                - ``update_validation_issues_view``
        """
        for i, row in enumerate(visible_rows):
            style = visible_styles[i] if i < len(visible_styles) else ""
            rich_cells = tuple(Text(str(cell), style=style) if style else Text(str(cell)) for cell in row)
            absolute_index = index_base + i
            row_key = f"issue:{absolute_index}"
            if i < len(visible_issues):
                self._issue_row_key_to_index[row_key] = absolute_index
            try:
                issue_table.add_row(*rich_cells, key=row_key)
            except Exception:
                issue_table.add_row(*rich_cells)

    def action_validation_issues_page_next(self) -> None:
        """Advance the validation-issues viewer window by one configured page."""
        total = len(self._filtered_validation_issues())
        if total == 0:
            return
        page_size = self._clamp_viewer_page_size(self.validation_issues_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._validation_issues_window_start = min(
            max_start, self._validation_issues_window_start + page_size
        )
        self.update_validation_issues_view()

    def action_validation_issues_page_prev(self) -> None:
        """Rewind the validation-issues viewer window by one configured page."""
        if not self._validation_issues:
            return
        page_size = self._clamp_viewer_page_size(self.validation_issues_page_size)
        self._validation_issues_window_start = max(
            0, self._validation_issues_window_start - page_size
        )
        self.update_validation_issues_view()

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
        self.logger.info("Load phase boundary: mac_parse_entry path=%s", path.name)
        self._flush_logger()
        parse_started = time.perf_counter()
        mac_data = parse_mac_file(path)
        records = mac_data.get("records", [])
        diagnostics = [str(item) for item in mac_data.get("diagnostics", [])]
        self.logger.info(
            "Load phase boundary: mac_parse_done path=%s rows=%d diagnostics=%d elapsed=%.3fs",
            path.name,
            len(records),
            len(diagnostics),
            time.perf_counter() - parse_started,
        )
        # Mirror the mac.py-level summary into the s19tui logger so users who only
        # check the app's rotating log file see the same key/value breakdown that
        # the root logger emits.
        parse_ok_count = len([item for item in records if item.get("parse_ok")])
        valid_from_records = len(
            [item for item in records if isinstance(item.get("address"), int)]
        )
        self.logger.info(
            "MAC parse summary (mirrored): path=%s rows=%d parse_ok=%d diagnostics=%d valid_addresses=%d",
            path,
            len(records),
            parse_ok_count,
            len(diagnostics),
            valid_from_records,
        )
        self._flush_logger()
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
        self.logger.info(
            "Load phase boundary: mac_a2l_resolve_entry path=%s a2l_path=%s",
            path.name,
            a2l_path,
        )
        self._flush_logger()
        a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
        self.logger.info(
            "Load phase boundary: mac_a2l_resolve_done path=%s has_a2l_data=%s",
            path.name,
            bool(a2l_data),
        )
        self._flush_logger()
        self.logger.info(
            "MAC parse summary: path=%s total_records=%d parse_ok=%d diagnostics=%d valid_addresses=%d a2l_path=%s elapsed_seconds=%.3f",
            path,
            len(records),
            parse_ok_count,
            len(diagnostics),
            len(valid_addresses),
            a2l_path,
            time.perf_counter() - parse_started,
        )
        self._flush_logger()
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

    def _get_range_index(self, loaded: Optional[LoadedFile]) -> tuple[list[int], list[int]]:
        """
        Summary:
            Return a cached sorted (starts, ends) index for a ``LoadedFile``'s ranges, building
            it lazily on first access so repeated address-in-ranges checks scale at O(log R).

        Args:
            loaded (Optional[LoadedFile]): Payload whose ranges should be indexed; ``None``
                yields an empty index.

        Returns:
            tuple[list[int], list[int]]: Parallel ``(starts, ends)`` lists suitable for
            ``address_in_sorted_ranges``.

        Data Flow:
            - Return empty index when ``loaded`` is missing or carries no ranges.
            - Reuse cached ``loaded.range_index`` when present.
            - Build and cache via ``build_sorted_range_index`` otherwise.

        Dependencies:
            Uses:
                - ``build_sorted_range_index``
            Used by:
                - ``_mac_address_in_ranges``
                - ``_collect_mac_out_of_range_addresses``
                - ``_build_mac_view_cache``
        """
        if loaded is None or not loaded.ranges:
            return ([], [])
        cached = getattr(loaded, "range_index", None)
        if cached is not None:
            return cached
        index = build_sorted_range_index(loaded.ranges)
        try:
            loaded.range_index = index
        except Exception:
            # If LoadedFile was constructed by test code without the new field, fall back
            # to returning the fresh index without mutating the payload.
            pass
        return index

    def _mac_address_in_ranges(self, address: int, ranges: list[tuple[int, int]]) -> bool:
        """
        Summary:
            Test an address against a list of ranges using binary search over a sorted index.

        Args:
            address (int): Address to check.
            ranges (list[tuple[int, int]]): Half-open ``(start, end)`` ranges; these are
                indexed once per call, which keeps the signature stable but is slower than
                passing a pre-built index via ``_get_range_index``.

        Returns:
            bool: True when ``address`` falls inside any of the provided ranges.

        Data Flow:
            - Build a sorted ``(starts, ends)`` index on the fly.
            - Delegate the actual check to ``address_in_sorted_ranges``.

        Dependencies:
            Uses:
                - ``build_sorted_range_index``
                - ``address_in_sorted_ranges``
        """
        if not ranges:
            return False
        return address_in_sorted_ranges(address, build_sorted_range_index(ranges))

    def _collect_mac_out_of_range_addresses(self, loaded: Optional[LoadedFile]) -> set[int]:
        """
        Summary:
            Collect MAC addresses that fall outside the current primary image's ranges.

        Args:
            loaded (Optional[LoadedFile]): Active payload; must be an S19/HEX primary for
                the check to apply.

        Returns:
            set[int]: Out-of-range MAC addresses.

        Data Flow:
            - Short-circuit when no primary image is attached.
            - Resolve the cached sorted range index once via ``_get_range_index``.
            - Iterate MAC records and test each parsed address against the index.

        Dependencies:
            Uses:
                - ``_get_range_index``
                - ``address_in_sorted_ranges``
            Used by:
                - ``update_sections``
        """
        if not loaded or loaded.file_type not in {"s19", "hex"}:
            return set()
        range_index = self._get_range_index(loaded)
        if not range_index[0]:
            return {
                int(record["address"])
                for record in (loaded.mac_records or [])
                if record.get("parse_ok") and isinstance(record.get("address"), int)
            }
        out_of_range: set[int] = set()
        for record in loaded.mac_records or []:
            address = record.get("address")
            if not (record.get("parse_ok") and isinstance(address, int)):
                continue
            if not address_in_sorted_ranges(address, range_index):
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

    def _merge_primary_with_existing_mac(self, primary_loaded: LoadedFile) -> LoadedFile:
        """
        Summary:
            Preserve currently attached MAC payload when a new S19/HEX primary image is loaded.

        Args:
            primary_loaded (LoadedFile): Newly parsed primary artifact payload (``s19`` or ``hex``).

        Returns:
            LoadedFile: Primary payload with MAC metadata copied from the current session when available.

        Data Flow:
            - Return incoming primary payload unchanged when no current file exists.
            - If the current file has MAC metadata, copy ``mac_path``, ``mac_records``, and diagnostics.
            - Keep primary fields (memory map/ranges/errors) from the newly loaded artifact.

        Dependencies:
            Uses:
                - ``LoadedFile`` dataclass constructor
            Used by:
                - ``load_selected_file`` primary branches
        """
        existing = self.current_file
        if existing is None:
            return primary_loaded
        if not existing.mac_path and not existing.mac_records and not existing.mac_diagnostics:
            return primary_loaded
        return LoadedFile(
            path=primary_loaded.path,
            file_type=primary_loaded.file_type,
            mem_map=primary_loaded.mem_map,
            row_bases=primary_loaded.row_bases,
            ranges=primary_loaded.ranges,
            range_validity=primary_loaded.range_validity,
            errors=primary_loaded.errors,
            a2l_path=primary_loaded.a2l_path or existing.a2l_path,
            a2l_data=primary_loaded.a2l_data or existing.a2l_data,
            mac_path=existing.mac_path,
            mac_records=existing.mac_records,
            mac_diagnostics=existing.mac_diagnostics,
            # A new primary is a new image: keep the incoming payload's
            # variant identity (stamped at apply time), never the old one.
            variant_id=primary_loaded.variant_id,
        )

    def _merge_mac_with_existing_primary(self, mac_loaded: LoadedFile) -> LoadedFile:
        """
        Summary:
            Attach parsed MAC metadata to the active S19/HEX payload when one is already loaded.

        Args:
            mac_loaded (LoadedFile): Parsed MAC payload from ``_load_mac_file``.

        Returns:
            LoadedFile: Existing primary payload with refreshed MAC fields, or ``mac_loaded`` when no primary exists.

        Data Flow:
            - Detect whether current state contains a primary ``s19``/``hex`` payload.
            - When primary exists, keep its memory/range fields and overlay MAC fields from ``mac_loaded``.
            - Keep the best available A2L path/data between primary and MAC payload.

        Dependencies:
            Uses:
                - ``LoadedFile`` dataclass constructor
            Used by:
                - ``load_selected_file`` MAC branch
        """
        existing = self.current_file
        if not existing or existing.file_type not in {"s19", "hex"}:
            return mac_loaded
        return LoadedFile(
            path=existing.path,
            file_type=existing.file_type,
            mem_map=existing.mem_map,
            row_bases=existing.row_bases,
            ranges=existing.ranges,
            range_validity=existing.range_validity,
            errors=existing.errors,
            a2l_path=mac_loaded.a2l_path or existing.a2l_path,
            a2l_data=mac_loaded.a2l_data or existing.a2l_data,
            mac_path=mac_loaded.mac_path,
            mac_records=mac_loaded.mac_records,
            mac_diagnostics=mac_loaded.mac_diagnostics,
            # The primary image is unchanged — its variant identity survives
            # the MAC overlay (project MAC follow-up load, LLR-005.6).
            variant_id=existing.variant_id,
        )

    def _invalidate_mac_view_cache(self) -> None:
        """
        Summary:
            Clear cached MAC table/validation material so next render recomputes from current state.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reset cache key and cached row/meta payload.
            - Reset cached summaries and coverage line.

        Dependencies:
            Used by:
                - ``load_selected_file`` after artifact changes
                - settings handlers that alter MAC row semantics
        """
        self._mac_view_cache_key = None
        self._mac_view_cache_rows = []
        self._mac_view_cache_meta = []
        self._mac_view_cache_summary = {}
        self._mac_view_cache_coverage_line = None
        self._mac_view_cache_widths = None
        self._mac_view_cache_cell_rows = []
        self._mac_view_cache_cell_styles = []
        self._validation_issue_cell_rows = []
        self._validation_issue_cell_styles = []

    def _compute_mac_view_payload(
        self,
        loaded: Optional[LoadedFile],
        a2l_data: Optional[dict],
        a2l_enriched_tags: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """
        Summary:
            Pure (thread-safe) builder for the MAC table rows, summary counters, and the
            cross-artifact validation report that feeds the Issues panel.

        Args:
            loaded (Optional[LoadedFile]): Parsed payload to validate; may be ``None``.
            a2l_data (Optional[dict]): Parsed A2L payload used for name-index lookup.
            a2l_enriched_tags (Optional[list[dict]]): Pre-enriched A2L tag list; falls back
                to raw ``a2l_data["tags"]`` when missing so the function stays self-contained.

        Returns:
            dict[str, Any]: ``{"rows", "meta", "summary", "coverage_line", "report",
                "issues"}``. ``report`` and ``issues`` are ``None``/``[]`` when ``loaded``
                is not an S19/HEX primary.

        Data Flow:
            - Classify the payload as primary-backed or MAC-only.
            - Walk MAC records once to build row tuples, severity metadata, and counters,
              using the sorted range index for O(log R) membership checks.
            - On primary payloads, run ``validate_artifact_consistency`` plus the A2L
              internal-issue pass and dedupe the resulting issue list.

        Dependencies:
            Uses:
                - ``_build_a2l_name_index``
                - ``_mac_record_ui_state``
                - ``build_sorted_range_index`` / ``address_in_sorted_ranges``
                - ``validate_artifact_consistency`` / ``validate_a2l_internal_issues``
                - ``_deduplicate_issues``
            Used by:
                - ``_prepare_load_payload`` (worker thread)
                - ``_build_mac_view_cache`` (synchronous fallback)
        """
        records = loaded.mac_records if loaded else []
        has_a2l = bool(a2l_data)
        a2l_name_index = _build_a2l_name_index(a2l_data)
        primary_file = (
            loaded
            if loaded is not None and loaded.file_type in {"s19", "hex"}
            else None
        )
        if primary_file is not None:
            cached_index = getattr(primary_file, "range_index", None)
            if cached_index is not None:
                range_index = cached_index
            else:
                range_index = build_sorted_range_index(primary_file.ranges)
        else:
            range_index = ([], [])
        rows: list[tuple[str, str, str, str, str, str, str, str]] = []
        row_meta: list[dict[str, Any]] = []
        total_verified = 0
        total_invalid = 0
        total_neutral = 0
        total_in_a2l = 0
        total_out_of_mem = 0
        total_parse_errors = 0
        for record in records or []:
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
            if primary_file is not None and isinstance(address, int):
                memory_checked = True
                in_memory = address_in_sorted_ranges(address, range_index)
            in_mem_text = "n/a"
            if memory_checked:
                in_mem_text = "yes" if in_memory else "no"
                if not in_memory:
                    total_out_of_mem += 1
            status, severity_text = _mac_record_ui_state(record, a2l_name_index, has_a2l, memory_checked, in_memory)
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
            row_meta.append({"severity": severity, "address": address if isinstance(address, int) else None})
        summary = {
            "total": len(rows),
            "verified": total_verified,
            "invalid": total_invalid,
            "neutral": total_neutral,
            "in_a2l": total_in_a2l,
            "out_of_mem": total_out_of_mem,
            "parse_errors": total_parse_errors,
        }
        coverage_line: Optional[str] = None
        report: Optional[ValidationReport] = None
        issues: list[ValidationIssue] = []
        if loaded is not None:
            validate_started = time.perf_counter()
            overlap_set = set()
            if primary_file is not None and primary_file.file_type == "s19":
                try:
                    overlap_set = set(S19File(str(primary_file.path)).get_overlap_addresses())
                except Exception as exc:
                    self.logger.warning(
                        "Failed to compute overlap set for %s: %s",
                        primary_file.path,
                        exc,
                    )
                    overlap_set = set()
            report, issues, coverage_line = build_validation_report(
                records=records,
                primary_file=primary_file,
                a2l_data=a2l_data,
                a2l_enriched_tags=a2l_enriched_tags,
                dedupe_issues=self._deduplicate_issues,
                overlapped_addresses=overlap_set,
            )
            self.logger.info(
                "MAC validation computed: records=%d issues=%d elapsed_seconds=%.3f",
                len(records or []),
                len(issues),
                time.perf_counter() - validate_started,
            )
        return {
            "rows": rows,
            "meta": row_meta,
            "summary": summary,
            "coverage_line": coverage_line,
            "report": report,
            "issues": issues,
        }

    def _build_mac_view_cache(self) -> None:
        """
        Summary:
            Populate the MAC view cache members from ``_compute_mac_view_payload`` for the
            synchronous fallback path (tests, project load, and non-worker invocations).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Call ``_compute_mac_view_payload`` with the currently attached file and A2L data.
            - Mirror its result onto ``self._mac_view_cache_*`` and the validation members.

        Dependencies:
            Uses:
                - ``_compute_mac_view_payload``
            Used by:
                - ``update_mac_view`` when the cache key has not been pre-populated
        """
        started = time.perf_counter()
        payload = self._compute_mac_view_payload(
            self.current_file,
            self.current_a2l_data,
            a2l_enriched_tags=self._a2l_enriched_tags,
        )
        self._mac_view_cache_rows = payload["rows"]
        self._mac_view_cache_meta = payload["meta"]
        self._mac_view_cache_summary = payload["summary"]
        self._mac_view_cache_coverage_line = payload["coverage_line"]
        self._validation_report = payload["report"]
        self._validation_issues = list(payload["issues"])
        widths, cell_rows, cell_styles = precompute_mac_datatable_payload(
            payload["rows"], payload["meta"]
        )
        self._mac_view_cache_widths = widths
        self._mac_view_cache_cell_rows = cell_rows
        self._mac_view_cache_cell_styles = cell_styles
        issue_cells, issue_styles = precompute_issue_datatable_payload(list(payload["issues"]))
        self._validation_issue_cell_rows = issue_cells
        self._validation_issue_cell_styles = issue_styles
        self.logger.info(
            "MAC row cache built: records=%d elapsed_seconds=%.3f",
            len(self.current_file.mac_records) if self.current_file else 0,
            time.perf_counter() - started,
        )

    def load_selected_file(self, path: Path, a2l_files: Optional[list[Path]] = None) -> None:
        """
        Summary:
            Synchronously load S19, Intel HEX, or MAC data from disk and refresh all TUI panels
            that depend on ``current_file`` and optional A2L state.

        Args:
            path (Path): File to parse (extension selects loader branch).
            a2l_files (Optional[list[Path]]): Optional A2L paths when loading from a project
                directory (first file used).

        Returns:
            None

        Data Flow:
            - Parse the file into a ``LoadedFile`` via ``_parse_loaded_file`` (pure CPU work).
            - On parse error, surface the error through ``set_status`` and abort.
            - On unsupported extension, return with a status message.
            - Otherwise apply the payload to reactive state and refresh views via
              ``_apply_loaded_file``.

        Dependencies:
            Uses:
                - ``_parse_loaded_file``
                - ``_apply_loaded_file``
            Used by:
                - ``load_from_path`` fallback path
                - project load handler (``_handle_load_project``)
                - workarea file list selection
                - unit tests that drive the synchronous pipeline directly
        """
        load_started = time.perf_counter()
        try:
            loaded = self._parse_loaded_file(path, a2l_files)
        except Exception as exc:
            self._pending_variant_id = None
            self.set_status(f"Load failed: {exc}")
            self.logger.exception(
                "Load failed for path=%s suffix=%s project=%s",
                path,
                path.suffix.lower(),
                self.current_project,
            )
            return
        if loaded is None:
            self._pending_variant_id = None
            suffix = path.suffix.lower()
            self.set_status(f"Unsupported file type: {suffix}")
            self.logger.warning("Unsupported file type in loader: %s", suffix)
            return
        self._apply_loaded_file(loaded, path, load_started)

    def _parse_loaded_file(
        self, path: Path, a2l_files: Optional[list[Path]] = None
    ) -> Optional[LoadedFile]:
        """
        Summary:
            Parse an S19/HEX/MAC file into a ``LoadedFile`` payload without touching UI state.

        Args:
            path (Path): File to parse (extension selects loader branch).
            a2l_files (Optional[list[Path]]): Optional A2L paths when loading from a project
                directory (first file used).

        Returns:
            Optional[LoadedFile]: Parsed and merged payload ready for application, or ``None``
            when the suffix is unsupported.

        Raises:
            Exception: Propagates any parsing exception; callers must handle or log.

        Data Flow:
            - Dispatch on suffix to S19, HEX, or MAC construction of ``LoadedFile``.
            - For primary (S19/HEX) images, merge any existing MAC payload via
              ``_merge_primary_with_existing_mac``.
            - For MAC files, overlay on existing primary via ``_merge_mac_with_existing_primary``.
            - Log loader-specific summaries.

        Dependencies:
            Uses:
                - ``S19File`` / ``IntelHexFile`` / ``_load_mac_file``
                - ``build_mem_map_s19``, ``build_row_bases``, range validity builders
                - ``_load_a2l_data_with_cache``
                - ``_merge_primary_with_existing_mac`` / ``_merge_mac_with_existing_primary``
            Used by:
                - ``load_selected_file`` (synchronous path)
                - ``_start_load_worker`` (threaded path)
        """
        suffix = path.suffix.lower()
        self.logger.info(
            "Loading file: path=%s suffix=%s project=%s",
            path,
            suffix,
            self.current_project,
        )
        self.logger.info(
            "Load phase boundary: parse_branch_entry path=%s suffix=%s",
            path.name,
            suffix,
        )
        self._flush_logger()
        if suffix in S19_EXTENSIONS:
            s19 = S19File(str(path))
            a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
            a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
            loaded = build_loaded_s19(path, s19, a2l_path, a2l_data)
            loaded = self._merge_primary_with_existing_mac(loaded)
            self._log_loaded_file_summary(
                file_type="s19",
                path=path,
                mem_map=loaded.mem_map,
                ranges=loaded.ranges,
                errors=loaded.errors,
            )
            self.logger.info(
                "Load phase boundary: parse_branch_done path=%s branch=s19",
                path.name,
            )
            self._flush_logger()
            return loaded
        if suffix in HEX_EXTENSIONS:
            hex_file = IntelHexFile(str(path))
            a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
            a2l_data = self._load_a2l_data_with_cache(a2l_path) if a2l_path else self.current_a2l_data
            loaded = build_loaded_hex(path, hex_file, a2l_path, a2l_data)
            loaded = self._merge_primary_with_existing_mac(loaded)
            self._log_loaded_file_summary(
                file_type="hex",
                path=path,
                mem_map=loaded.mem_map,
                ranges=loaded.ranges,
                errors=loaded.errors,
            )
            self.logger.info(
                "Load phase boundary: parse_branch_done path=%s branch=hex",
                path.name,
            )
            self._flush_logger()
            return loaded
        if suffix in MAC_EXTENSIONS:
            mac_loaded = self._load_mac_file(path, a2l_files)
            self.logger.info(
                "Load phase boundary: mac_merge_entry path=%s has_primary=%s",
                path.name,
                bool(
                    self.current_file
                    and self.current_file.file_type in {"s19", "hex"}
                ),
            )
            self._flush_logger()
            loaded = self._merge_mac_with_existing_primary(mac_loaded)
            self.logger.info(
                "Load phase boundary: mac_merge_done path=%s file_type=%s",
                path.name,
                loaded.file_type,
            )
            self._flush_logger()
            if loaded.file_type in {"s19", "hex"}:
                self._log_loaded_file_summary(
                    file_type=f"{loaded.file_type}+mac",
                    path=path,
                    mem_map=loaded.mem_map,
                    ranges=loaded.ranges,
                    errors=loaded.errors,
                )
            else:
                self._log_loaded_file_summary(
                    file_type="mac",
                    path=path,
                    mem_map=loaded.mem_map,
                    ranges=loaded.ranges,
                    errors=loaded.errors,
                )
            self.logger.info(
                "Load phase boundary: parse_branch_done path=%s branch=mac",
                path.name,
            )
            self._flush_logger()
            return loaded
        return None

    def _apply_loaded_file(self, loaded: LoadedFile, path: Path, load_started: float) -> None:
        """
        Summary:
            Synchronous-path wrapper: build a non-precomputed ``PreparedLoad`` and delegate
            to ``_apply_prepared_load`` so tests and project load share one install code path.

        Args:
            loaded (LoadedFile): Parsed payload from ``_parse_loaded_file``.
            path (Path): Source path used for status messaging and log lines.
            load_started (float): ``time.perf_counter`` value captured at pipeline start.

        Returns:
            None

        Data Flow:
            - Wrap ``loaded`` into a ``PreparedLoad(precomputed=False)``.
            - Forward to ``_apply_prepared_load`` so legacy callers keep working without
              the worker-thread precompute step.

        Dependencies:
            Uses:
                - ``_apply_prepared_load``
            Used by:
                - ``load_selected_file`` (synchronous path)
        """
        self._apply_prepared_load(PreparedLoad(loaded=loaded), path, load_started)

    def _apply_prepared_load(
        self, prepared: PreparedLoad, path: Path, load_started: float
    ) -> None:
        """
        Summary:
            Install a ``PreparedLoad`` onto reactive state and refresh every dependent UI
            panel, relying on worker-precomputed caches to avoid heavy main-thread work.

        Args:
            prepared (PreparedLoad): Bundle of parsed payload plus optional precomputed
                MAC cache, validation issues, highlights, out-of-range list, and bases set.
            path (Path): Source path used for status messaging and log lines.
            load_started (float): ``time.perf_counter`` value captured at pipeline start.

        Returns:
            None

        Data Flow:
            - Mutate ``current_file``, reset MAC/hex/issues paging anchors, and sync A2L.
            - When ``precomputed`` is True, copy MAC cache + validation results into the
              app's cache members so ``update_mac_view`` treats them as a cache hit.
            - Attach ``bases_set`` to the ``LoadedFile`` for fast hex rendering.
            - Set the coexistence status line immediately so the user sees the new file.
            - Schedule sections, hex, A2L, and project-label refreshes via ``call_later``
              so the event loop can process the modal-pop message and repaint between
              each phase instead of blocking the UI for the full install duration.

        Dependencies:
            Uses:
                - ``_invalidate_mac_view_cache`` / ``_flush_logger``
                - ``call_later`` (yielding chain)
                - ``update_sections`` / ``update_hex_view`` / ``update_alt_hex_view`` /
                  ``update_mac_hex_view`` / ``update_mac_view`` / ``update_a2l_view`` /
                  ``update_project_labels`` / ``update_memory_map``
            Used by:
                - ``_start_load_worker`` (threaded path)
                - ``_apply_loaded_file`` (synchronous fallback)
        """
        loaded = prepared.loaded
        # Variant stamping happens HERE, at apply time on the main UI thread:
        # the pending id was set on the main thread by the dispatching handler
        # (project load / variant selector), the parse worker never reads it,
        # and the worker signatures stay untouched (LLR-005.4 thread contract).
        pending_variant = self._pending_variant_id
        if pending_variant is not None and loaded.file_type in {"s19", "hex"}:
            loaded.variant_id = pending_variant
            self._pending_variant_id = None
            if self._variant_set is not None and any(
                variant.variant_id == pending_variant
                for variant in self._variant_set.variants
            ):
                self._variant_set.active_id = pending_variant
        self.current_file = loaded
        # A file is now present — reveal the real content of the
        # content-bearing rail screens and hide their empty-state panels
        # (LLR-002.3).
        self._apply_empty_state()
        self._invalidate_mac_view_cache()
        self._mac_window_start = 0
        self._validation_issues_window_start = 0
        self._a2l_tag_hex_highlight = None
        # A new file invalidates every per-view goto focus address (LLR-003.6 file-load).
        self._goto_focus_address = None
        self._alt_goto_focus_address = None
        self._mac_goto_focus_address = None
        if loaded.a2l_data:
            self.current_a2l_path = loaded.a2l_path
            self.current_a2l_data = loaded.a2l_data
        # Attach worker-precomputed bases_set so hex renders skip rebuilding sets of
        # millions of addresses on every refresh.
        try:
            if prepared.bases_set is not None:
                loaded.bases_set = prepared.bases_set
        except Exception:
            # Legacy LoadedFile in test fixtures may not support the attribute; ignore.
            pass
        if prepared.precomputed:
            self._mac_view_cache_key = prepared.mac_cache_key
            self._mac_view_cache_rows = prepared.mac_rows
            self._mac_view_cache_meta = prepared.mac_meta
            self._mac_view_cache_summary = prepared.mac_summary
            self._mac_view_cache_coverage_line = prepared.mac_coverage_line
            self._validation_report = prepared.validation_report
            self._validation_issues = list(prepared.validation_issues)
            # Stash worker-precomputed DataTable payloads so the populate helpers
            # skip re-formatting cells on the UI thread.
            self._mac_view_cache_widths = prepared.mac_widths
            self._mac_view_cache_cell_rows = list(prepared.mac_cell_rows)
            self._mac_view_cache_cell_styles = list(prepared.mac_cell_styles)
            self._validation_issue_cell_rows = list(prepared.issue_cell_rows)
            self._validation_issue_cell_styles = list(prepared.issue_cell_styles)
            if prepared.a2l_enriched_key is not None:
                self._a2l_enriched_tags = prepared.a2l_enriched_tags
                self._a2l_enriched_key = prepared.a2l_enriched_key
                self._a2l_summary_lines = prepared.a2l_summary_lines
                self._a2l_summary_start = 0
        # Surface the new file name right away so the user sees immediate feedback
        # even before the deferred sections/hex/a2l refreshes complete.
        status_message = self._format_coexistence_status(loaded, path)
        self.set_file_status(status_message)
        self._append_log_line(status_message)
        self.logger.info(
            "Load phase boundary: apply_install_state path=%s precomputed=%s",
            path.name,
            prepared.precomputed,
        )
        self._flush_logger()

        precomputed_oor = prepared.mac_out_of_range if prepared.precomputed else None

        def _step_sections() -> None:
            try:
                if precomputed_oor is not None:
                    self.update_sections(precomputed_out_of_range=precomputed_oor)
                else:
                    self.update_sections()
            finally:
                self.logger.info(
                    "Load phase boundary: apply_sections_done path=%s", path.name
                )
                self._flush_logger()
                self.call_later(_step_hex)

        def _step_hex() -> None:
            try:
                self.update_hex_view()
                self.update_alt_hex_view()
                self.update_mac_hex_view()
            finally:
                self.logger.info(
                    "Load phase boundary: apply_hex_done path=%s", path.name
                )
                self._flush_logger()
                self.call_later(_step_a2l)

        def _step_a2l() -> None:
            try:
                # ``update_a2l_view`` invokes ``update_mac_view`` internally in both
                # A2L present/absent branches, which in turn installs the precomputed
                # cache and renders the validation-issues window.
                self.update_a2l_view()
            finally:
                self.logger.info(
                    "Load phase boundary: apply_a2l_done path=%s", path.name
                )
                self._flush_logger()
                self.call_later(_step_finalize)

        def _step_finalize() -> None:
            try:
                self.update_project_labels()
                self.update_memory_map()
            finally:
                total_elapsed = time.perf_counter() - load_started
                self.logger.info(
                    "Loaded file successfully: path=%s file_type=%s elapsed_seconds=%.3f has_mac=%s precomputed=%s",
                    path,
                    loaded.file_type,
                    total_elapsed,
                    bool(loaded.mac_records),
                    prepared.precomputed,
                )
                self._flush_logger()

        self.call_later(_step_sections)

    def _format_coexistence_status(self, loaded: LoadedFile, path: Path) -> str:
        """
        Summary:
            Compose a short status line that reflects whether S19/HEX and MAC coexist.

        Args:
            loaded (LoadedFile): Payload about to be rendered.
            path (Path): Current source file used for the human-readable name.

        Returns:
            str: Status text for the file-status label, activity log, and progress bar.

        Data Flow:
            - Classify the loaded payload as primary-only, MAC-only, or primary+MAC.
            - Include the source file name and, when available, an attached MAC name.

        Dependencies:
            Used by:
                - ``_apply_loaded_file``
        """
        if loaded.file_type in {"s19", "hex"} and loaded.mac_records:
            if loaded.mac_path and loaded.mac_path != path:
                return (
                    f"Loaded {path.name} ({loaded.file_type.upper()}+MAC: "
                    f"{loaded.mac_path.name})"
                )
            return f"Loaded {path.name} ({loaded.file_type.upper()}+MAC)"
        if loaded.file_type in {"s19", "hex"}:
            return f"Loaded {path.name} ({loaded.file_type.upper()} only)"
        if loaded.file_type == "mac":
            return f"Loaded {path.name} (MAC only)"
        return f"Loaded {path.name}"

    def _prepare_load_payload(self, loaded: LoadedFile) -> PreparedLoad:
        """
        Summary:
            Build every derived artifact the UI needs from a freshly parsed ``LoadedFile``,
            so the main thread only has to install them onto widgets.

        Args:
            loaded (LoadedFile): Parsed payload from ``_parse_loaded_file``.

        Returns:
            PreparedLoad: Bundle with MAC cache, validation report, highlights,
            out-of-range list, ``bases_set``, and A2L enrichment state.

        Data Flow:
            - Pre-compute enriched A2L tags (or skip when no A2L present).
            - Run ``_compute_mac_view_payload`` to produce the MAC table + validation output.
            - Derive MAC highlights and sorted out-of-range lists using the cached
              ``range_index``.
            - Freeze the ``row_bases`` into a ``frozenset`` so hex renders avoid rebuilding
              million-entry sets on every refresh.
            - Pack everything into a ``PreparedLoad`` with a matching ``mac_cache_key`` so
              ``update_mac_view`` treats the payload as a cache hit.

        Dependencies:
            Uses:
                - ``enrich_tags_and_render``
                - ``_compute_mac_view_payload``
                - ``_get_range_index`` / ``address_in_sorted_ranges``
            Used by:
                - ``_start_load_worker``
        """
        self.logger.info(
            "Load phase boundary: prepare_entry path=%s file_type=%s",
            loaded.path.name if getattr(loaded, "path", None) else "?",
            loaded.file_type,
        )
        self._flush_logger()
        range_index = self._get_range_index(loaded if loaded.file_type in {"s19", "hex"} else None)
        a2l_data = loaded.a2l_data
        a2l_enriched_tags: list[dict[str, Any]] = []
        a2l_enriched_key: Optional[tuple] = None
        a2l_summary_lines: list[str] = []
        if a2l_data:
            mem_map = loaded.mem_map
            a2l_enriched_tags, a2l_summary_lines = enrich_tags_and_render(
                a2l_data,
                mem_map,
                max_tag_lines=500,
            )
            a2l_enriched_key = (id(a2l_data), len(mem_map))
        self.logger.info(
            "Load phase boundary: prepare_a2l_done has_a2l=%s enriched_tags=%d",
            bool(a2l_data),
            len(a2l_enriched_tags),
        )
        self._flush_logger()
        mac_payload = self._compute_mac_view_payload(
            loaded, a2l_data, a2l_enriched_tags=a2l_enriched_tags
        )
        self.logger.info(
            "Load phase boundary: prepare_mac_payload_done rows=%d issues=%d",
            len(mac_payload.get("rows", [])),
            len(mac_payload.get("issues", [])),
        )
        self._flush_logger()
        mac_highlights: set[int] = set()
        out_of_range: set[int] = set()
        has_primary = loaded.file_type in {"s19", "hex"}
        has_range_index = bool(range_index[0])
        for record in loaded.mac_records or []:
            addr = record.get("address")
            if not (record.get("parse_ok") and isinstance(addr, int)):
                continue
            mac_highlights.add(addr)
            if has_primary:
                if not has_range_index:
                    out_of_range.add(addr)
                elif not address_in_sorted_ranges(addr, range_index):
                    out_of_range.add(addr)
        self.logger.info(
            "Load phase boundary: prepare_highlights_done highlights=%d out_of_range=%d",
            len(mac_highlights),
            len(out_of_range),
        )
        self._flush_logger()
        bases_set = frozenset(loaded.row_bases) if loaded.row_bases else frozenset()
        self.logger.info(
            "Load phase boundary: prepare_bases_done row_bases=%d",
            len(bases_set),
        )
        self._flush_logger()
        records = loaded.mac_records or []
        mac_cache_key = (
            id(records),
            len(records),
            id(a2l_data),
            loaded.file_type,
            tuple(loaded.ranges),
            len(loaded.mem_map),
        )
        mac_widths, mac_cell_rows, mac_cell_styles = precompute_mac_datatable_payload(
            mac_payload["rows"], mac_payload["meta"]
        )
        issue_cell_rows, issue_cell_styles = precompute_issue_datatable_payload(
            list(mac_payload["issues"])
        )
        self.logger.info(
            "Load phase boundary: prepare_datatable_done mac_rows=%d issues=%d widths=%s",
            len(mac_cell_rows),
            len(issue_cell_rows),
            mac_widths,
        )
        self._flush_logger()
        self.logger.info("Load phase boundary: prepare_done records=%d", len(records))
        self._flush_logger()
        return PreparedLoad(
            loaded=loaded,
            precomputed=True,
            mac_cache_key=mac_cache_key,
            mac_rows=mac_payload["rows"],
            mac_meta=mac_payload["meta"],
            mac_summary=mac_payload["summary"],
            mac_coverage_line=mac_payload["coverage_line"],
            validation_report=mac_payload["report"],
            validation_issues=list(mac_payload["issues"]),
            mac_highlights=frozenset(mac_highlights),
            mac_out_of_range=sorted(out_of_range),
            bases_set=bases_set,
            a2l_enriched_tags=a2l_enriched_tags,
            a2l_enriched_key=a2l_enriched_key,
            a2l_summary_lines=a2l_summary_lines,
            mac_widths=mac_widths,
            mac_cell_rows=mac_cell_rows,
            mac_cell_styles=mac_cell_styles,
            issue_cell_rows=issue_cell_rows,
            issue_cell_styles=issue_cell_styles,
        )

    @work(thread=True, exclusive=True, group="load")
    def _start_load_worker(
        self, path: Path, a2l_files: Optional[list[Path]] = None
    ) -> None:
        """
        Summary:
            Off-thread worker that parses a file, precomputes every derived artifact,
            and schedules a single UI install on the Textual main thread.

        Args:
            path (Path): Already-copied workarea file to parse.
            a2l_files (Optional[list[Path]]): Optional A2L paths from project load.

        Returns:
            None

        Data Flow:
            - Log a ``worker_parse_start`` phase marker and run ``_parse_loaded_file``.
            - Log ``worker_parse_done`` then call ``_prepare_load_payload`` to build the
              MAC cache, validation report, highlights, out-of-range list, and bases set.
            - Dispatch ``_apply_prepared_load`` via ``call_from_thread`` so the UI install
              is the only main-thread work performed for this load.
            - On parse or prepare exceptions, fall back to installing the minimal
              non-precomputed payload (or surface the error when the parse itself failed).

        Dependencies:
            Uses:
                - ``_parse_loaded_file`` / ``_prepare_load_payload``
                - ``call_from_thread``
                - ``_apply_prepared_load`` / ``_handle_load_error``
            Used by:
                - ``load_from_path`` (load dialog and startup path)
        """
        load_started = time.perf_counter()
        self.logger.info("Load phase boundary: worker_parse_start path=%s", path.name)
        self._flush_logger()
        try:
            loaded = self._parse_loaded_file(path, a2l_files)
        except Exception as exc:
            self.call_from_thread(self._handle_load_error, path, exc)
            return
        if loaded is None:
            suffix = path.suffix.lower()
            self.call_from_thread(
                self._handle_load_error,
                path,
                ValueError(f"Unsupported file type: {suffix}"),
            )
            return
        self.logger.info(
            "Load phase boundary: worker_parse_done path=%s elapsed=%.3fs",
            path.name,
            time.perf_counter() - load_started,
        )
        self._flush_logger()
        prepare_started = time.perf_counter()
        try:
            prepared = self._prepare_load_payload(loaded)
        except Exception as exc:
            # Fall back to the slow-path install so users still see the file.
            self.logger.exception("Prepare load payload failed; falling back: %s", exc)
            prepared = PreparedLoad(loaded=loaded)
        self.logger.info(
            "Load phase boundary: worker_compute_done path=%s precomputed=%s elapsed=%.3fs",
            path.name,
            prepared.precomputed,
            time.perf_counter() - prepare_started,
        )
        self._flush_logger()
        self.logger.info(
            "Load phase boundary: call_from_thread_apply_dispatched path=%s",
            path.name,
        )
        self._flush_logger()
        self.call_from_thread(self._apply_prepared_load, prepared, path, load_started)
        self.call_from_thread(self.set_progress, 100, f"Loaded {path.name}")
        if self.current_project:
            self.call_from_thread(self._sync_loaded_file_to_project)

    def _handle_load_error(self, path: Path, exc: Exception) -> None:
        """
        Summary:
            UI-thread handler for load-worker failures: update status/progress and log.

        Args:
            path (Path): Source path that failed to load.
            exc (Exception): Exception raised during parsing.

        Returns:
            None

        Data Flow:
            - Log the failure with full context.
            - Update status line and progress bar so the user sees the error.

        Dependencies:
            Used by:
                - ``_start_load_worker``
        """
        self._pending_variant_id = None
        self.logger.error(
            "Load failed for path=%s suffix=%s project=%s: %s",
            path,
            path.suffix.lower(),
            self.current_project,
            exc,
        )
        self.set_status(f"Load failed: {exc}")
        self.set_progress(100, "Load failed")

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

    def update_sections(self, precomputed_out_of_range: Optional[list[int]] = None) -> None:
        """
        Summary:
            Render the ranges/Sections panel and cap appended MAC out-of-range rows so
            very large MAC misalignments never mount thousands of widgets synchronously.

        Args:
            precomputed_out_of_range (Optional[list[int]]): Sorted MAC out-of-range
                addresses produced by the load worker; when ``None`` the app falls back
                to ``_collect_mac_out_of_range_addresses``.

        Returns:
            None

        Data Flow:
            - Clear widget and short-circuit when no file is loaded.
            - Append at most ``MAX_SECTIONS_PRIMARY_RANGES`` memory-range rows with
              OK/ERROR coloring, then a truncation row when more exist.
            - Append at most ``MAX_SECTIONS_OUT_OF_RANGE`` MAC out-of-range rows; when
              truncated, add a single summary row pointing users at the Issues panel.

        Dependencies:
            Uses:
                - ``_collect_mac_out_of_range_addresses``
                - ``css_class_for_severity``
            Used by:
                - ``_apply_prepared_load``
        """
        sections = self.query_one("#sections_list", ListView)
        sections.clear()
        if not self.current_file:
            return
        ranges = self.current_file.ranges
        validity = self.current_file.range_validity
        total_ranges = len(ranges)
        range_cap = MAX_SECTIONS_PRIMARY_RANGES
        visible_ranges = list(zip(ranges[:range_cap], validity[:range_cap]))
        for (start, end), is_valid in visible_ranges:
            size = end - start
            label = Label(f"0x{start:08X} - 0x{end - 1:08X} ({size} bytes)")
            severity = ValidationSeverity.OK if is_valid else ValidationSeverity.ERROR
            label.add_class(css_class_for_severity(severity))
            item = ListItem(label)
            item.data = (start, end)
            sections.append(item)
        if total_ranges > range_cap:
            extra_ranges = total_ranges - range_cap
            truncation_label = Label(
                f"... {extra_ranges} more ranges (see log) ..."
            )
            truncation_label.add_class(css_class_for_severity(ValidationSeverity.NEUTRAL))
            truncation_item = ListItem(truncation_label)
            truncation_item.data = None
            sections.append(truncation_item)
        if precomputed_out_of_range is not None:
            out_of_range = precomputed_out_of_range
        else:
            out_of_range = sorted(self._collect_mac_out_of_range_addresses(self.current_file))
        total_oor = len(out_of_range)
        oor_cap = MAX_SECTIONS_OUT_OF_RANGE
        visible = out_of_range[:oor_cap]
        for address in visible:
            label = Label(f"MAC out-of-range @ 0x{address:08X}")
            label.add_class("mac_out_of_range")
            item = ListItem(label)
            item.data = (address, address + 1)
            sections.append(item)
        if total_oor > oor_cap:
            truncation_label = Label(
                f"... {total_oor - oor_cap} more MAC out-of-range (see Issues panel) ..."
            )
            truncation_label.add_class("mac_out_of_range")
            sections.append(ListItem(truncation_label))
        self.logger.info(
            "Sections updated. count=%d rendered_ranges=%d mac_out_of_range_total=%d rendered_oor=%d",
            total_ranges,
            min(total_ranges, range_cap),
            total_oor,
            min(total_oor, oor_cap),
        )

    def update_memory_map(self) -> None:
        """
        Summary:
            Refresh the Memory Map screen's coverage visualization from the
            current ``LoadedFile`` (LLR-012.1).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When no file is loaded, hand empty lists to ``MemoryMapPanel``
              so it shows its neutral no-file note.
            - Otherwise pass ``current_file.ranges`` and
              ``current_file.range_validity`` straight through to
              ``MemoryMapPanel.render_ranges``. The renderer reads these
              already-computed model fields verbatim — it adds no coverage
              computation, parsing or analysis (LLR-012.1 / LLR-012.4).

        Dependencies:
            Uses:
                - ``MemoryMapPanel.render_ranges``
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
        """
        panel = self.query_one("#memory_map_panel", MemoryMapPanel)
        if not self.current_file:
            panel.render_ranges([], [])
            return
        panel.render_ranges(
            self.current_file.ranges,
            self.current_file.range_validity,
        )
        self.logger.info(
            "Memory Map updated. ranges=%d", len(self.current_file.ranges)
        )

    def update_hex_view(self, focus_address: Optional[int] = None) -> None:
        """Render hex view around a focus address if provided."""
        hex_view = self.query_one("#hex_view", Static)
        if not self.current_file:
            hex_view.update("No file loaded.")
            self._goto_focus_address = None
            return
        row_bases = self.current_file.row_bases or []
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        if row_bases:
            if isinstance(focus_address, int):
                focus_base = focus_address - (focus_address % 16)
                if focus_base in row_bases:
                    focus_index = row_bases.index(focus_base)
                    self._hex_window_start = (focus_index // page_size) * page_size
            max_start = max(0, ((len(row_bases) - 1) // page_size) * page_size)
            self._hex_window_start = max(0, min(self._hex_window_start, max_start))
        else:
            self._hex_window_start = 0
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=page_size,
                start_row_index=self._hex_window_start,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._goto_focus_address,
            )
        )
        if focus_address is not None:
            self.logger.info("Hex view focused at 0x%08X", focus_address)

    def _row_start_for_near_top_focus(
        self,
        focus_address: Optional[int],
        row_bases: list[int],
        context_rows: int = 1,
    ) -> Optional[int]:
        """Return a start-row index that keeps ``focus_address`` near the top."""
        if not isinstance(focus_address, int) or not row_bases:
            return None
        focus_base = focus_address - (focus_address % 16)
        try:
            focus_index = row_bases.index(focus_base)
        except ValueError:
            return None
        return max(0, focus_index - max(0, context_rows))

    def _reset_scroll_to_top(self, container_id: str) -> None:
        """Best-effort scroll reset for a hex scroll container."""
        try:
            container = self.query_one(container_id, ScrollableContainer)
        except Exception:
            return
        try:
            container.scroll_home(animate=False)
            return
        except Exception:
            pass
        try:
            container.scroll_y = 0
        except Exception:
            pass

    def update_alt_hex_view(
        self,
        focus_address: Optional[int] = None,
        near_top: bool = False,
        reset_scroll: bool = False,
    ) -> None:
        """
        Summary:
            Render the alternate hex panel with optional focus and a highlight span.

        Args:
            focus_address (Optional[int]): Focus the view on this address when set.
            near_top (bool): When True, anchor the focused address near the top rows.
            reset_scroll (bool): When True, reset alt hex scroll position to top.

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
            self._alt_first_visible_address = None
            self._alt_goto_focus_address = None
            return
        highlight = None
        if self._a2l_tag_hex_highlight is not None:
            highlight = self._a2l_tag_hex_highlight
        elif self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        row_bases = self.current_file.row_bases or []
        start_row_index = (
            self._row_start_for_near_top_focus(focus_address, row_bases) if near_top else None
        )
        if row_bases:
            effective_start = start_row_index if isinstance(start_row_index, int) else 0
            effective_start = max(0, min(effective_start, len(row_bases) - 1))
            self._alt_first_visible_address = row_bases[effective_start]
        else:
            self._alt_first_visible_address = None
        alt_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=self._clamp_viewer_page_size(self.hex_rows_page_size),
                start_row_index=start_row_index,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._alt_goto_focus_address,
            )
        )
        if reset_scroll:
            self._reset_scroll_to_top("#alt_hex_scroll")

    def update_mac_hex_view(
        self,
        focus_address: Optional[int] = None,
        near_top: bool = False,
        reset_scroll: bool = False,
    ) -> None:
        """Render MAC hex view around a focus address if provided."""
        mac_hex_view = self.query_one("#mac_hex_view", Static)
        if not self.current_file:
            mac_hex_view.update("No file loaded.")
            self._mac_first_visible_address = None
            self._mac_goto_focus_address = None
            return
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        row_bases = self.current_file.row_bases or []
        start_row_index = (
            self._row_start_for_near_top_focus(focus_address, row_bases) if near_top else None
        )
        if row_bases:
            effective_start = start_row_index if isinstance(start_row_index, int) else 0
            effective_start = max(0, min(effective_start, len(row_bases) - 1))
            self._mac_first_visible_address = row_bases[effective_start]
        else:
            self._mac_first_visible_address = None
        mac_hex_view.update(
            render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=self._clamp_viewer_page_size(self.hex_rows_page_size),
                start_row_index=start_row_index,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._mac_goto_focus_address,
            )
        )
        if reset_scroll:
            self._reset_scroll_to_top("#mac_hex_scroll")

    def update_mac_view(self) -> None:
        """
        Summary:
            Populate the MAC DataTable with a paged window of ``.mac`` rows plus an
            off-table summary label, consuming worker-precomputed cell rows so the UI
            thread only issues one ``clear`` + ``add_rows`` call.

        Args:
            None (reads ``current_file``, ``current_a2l_data``, ``#mac_records_list``,
            and ``#mac_records_summary``.)

        Returns:
            None

        Data Flow:
            - Short-circuit when no MAC records are loaded (empty table + summary).
            - Ensure the DataTable's MAC cache matches the current loaded state.
            - Slice one page of precomputed cell rows using ``mac_records_page_size``.
            - Build ``rich.text.Text`` cells keyed by severity and insert them via
              ``DataTable.add_rows`` in a single O(page_size) dict update.
            - Render aggregate counts and coverage into ``#mac_records_summary`` so the
              DataTable never has to hold summary rows.

        Dependencies:
            Uses:
                - ``_populate_mac_datatable``
                - ``update_validation_issues_view``
            Used by:
                - ``_apply_prepared_load`` post-load refresh
                - ``update_a2l_view`` when A2L data changes
                - MAC paging actions
        """
        populate_started = time.perf_counter()
        mac_table = self.query_one("#mac_records_list", DataTable)
        summary_label = self.query_one("#mac_records_summary", Label)
        self._mac_row_key_to_address = {}
        mac_table.clear(columns=False)
        if not self.current_file or not self.current_file.mac_records:
            summary_label.update("No MAC loaded.")
            self._validation_report = None
            self._validation_issues = []
            self._validation_issue_cell_rows = []
            self._validation_issue_cell_styles = []
            self.update_validation_issues_view()
            self.logger.info(
                "Load phase boundary: populate_mac_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        records = self.current_file.mac_records or []
        if not records:
            summary_label.update("No MAC records parsed.")
            self._validation_report = None
            self._validation_issues = []
            self._validation_issue_cell_rows = []
            self._validation_issue_cell_styles = []
            self.update_validation_issues_view()
            self.logger.info(
                "Load phase boundary: populate_mac_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        cache_key = (
            id(records),
            len(records),
            id(self.current_a2l_data),
            self.current_file.file_type,
            tuple(self.current_file.ranges),
            len(self.current_file.mem_map),
        )
        if self._mac_view_cache_key != cache_key:
            self._mac_view_cache_key = cache_key
            self._build_mac_view_cache()
        cell_rows = self._mac_view_cache_cell_rows or []
        cell_styles = self._mac_view_cache_cell_styles or []
        total = self._mac_view_cache_summary.get("total", len(cell_rows))
        self._mac_window_start = self._mac_clamp_page_start(total)
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        start, end = self._get_window_bounds(total, self._mac_window_start, page_size)
        self._mac_window_start = start
        visible_rows = cell_rows[start:end]
        visible_styles = cell_styles[start:end]
        visible_meta = self._mac_view_cache_meta[start:end]
        self._populate_mac_datatable(mac_table, visible_rows, visible_styles, visible_meta, start)
        page_num = start // page_size + 1
        total_pages = max(1, (total + page_size - 1) // page_size)
        summary_text = (
            f"Page {page_num}/{total_pages} | rows {start + 1}-{end} / {total} "
            f"(page size {page_size}; +/- for MAC page)  "
            f"Total={total}  Verified={self._mac_view_cache_summary.get('verified', 0)}  "
            f"Invalid={self._mac_view_cache_summary.get('invalid', 0)}  "
            f"Neutral={self._mac_view_cache_summary.get('neutral', 0)}  "
            f"NameInA2L={self._mac_view_cache_summary.get('in_a2l', 0)}  "
            f"OutOfMem={self._mac_view_cache_summary.get('out_of_mem', 0)}  "
            f"ParseErrs={self._mac_view_cache_summary.get('parse_errors', 0)}"
        )
        if self.current_file.file_type in {"s19", "hex"} and self._mac_view_cache_coverage_line:
            summary_text = f"{summary_text}\n{self._mac_view_cache_coverage_line}"
        summary_label.update(summary_text)
        self.update_validation_issues_view()
        self.logger.info(
            "Load phase boundary: populate_mac_table_done rows=%d total=%d elapsed=%.3f",
            len(visible_rows),
            total,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _populate_mac_datatable(
        self,
        mac_table: "DataTable",
        visible_rows: list[tuple[str, ...]],
        visible_styles: list[str],
        visible_meta: list[dict[str, Any]],
        start: int,
    ) -> None:
        """
        Summary:
            Insert one page of MAC rows into the MAC ``DataTable`` via a single
            ``add_rows`` call, recording a ``row_key -> address`` map so selection
            handlers can jump to the corresponding hex address.

        Args:
            mac_table (DataTable): Target table widget.
            visible_rows (list[tuple[str, ...]]): Precomputed cell strings for the page.
            visible_styles (list[str]): Rich style strings parallel to ``visible_rows``.
            visible_meta (list[dict]): Severity/address metadata parallel to rows.
            start (int): Absolute index of the first row in the page.

        Returns:
            None

        Data Flow:
            - Construct ``rich.text.Text`` cells so severity coloring renders correctly.
            - Build row-key strings of the form ``mac:<absolute_index>``.
            - Record the per-row address in ``_mac_row_key_to_address`` for jump logic.
            - Invoke ``DataTable.add_rows`` once with the fully-assembled iterable.

        Dependencies:
            Used by:
                - ``update_mac_view``
        """
        if not visible_rows:
            return
        rendered_rows: list[tuple] = []
        keys: list[str] = []
        for i, row in enumerate(visible_rows):
            style = visible_styles[i] if i < len(visible_styles) else ""
            rich_cells = tuple(Text(str(cell), style=style) if style else Text(str(cell)) for cell in row)
            rendered_rows.append(rich_cells)
            absolute_index = start + i
            row_key = f"mac:{absolute_index}"
            keys.append(row_key)
            meta = visible_meta[i] if i < len(visible_meta) else {}
            address = meta.get("address") if isinstance(meta, dict) else None
            if isinstance(address, int):
                self._mac_row_key_to_address[row_key] = address
        for key, row in zip(keys, rendered_rows):
            try:
                mac_table.add_row(*row, key=key)
            except Exception:
                mac_table.add_row(*row)

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
            - Use ``enrich_tags_and_render`` to compute merged tags and summary lines on cache miss.

        Dependencies:
            Uses:
                - ``enrich_tags_and_render``
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
        enriched, summary_lines = enrich_tags_and_render(
            self.current_a2l_data,
            mem_map,
            max_tag_lines=500,
        )
        self._a2l_enriched_tags = enriched
        self._a2l_enriched_key = key
        self._a2l_summary_lines = summary_lines
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
            Render one page of A2L tag rows into the A2L DataTable with row_keys
            that map back to the enriched tag dicts for jump handling.

        Args:
            tags (list[dict]): Filtered enriched tags to display (may be empty).

        Returns:
            None

        Data Flow:
            - Clear the DataTable (keep columns) and reset the row_key -> tag map.
            - Short-circuit when ``tags`` is empty (update summary text only).
            - Slice one page using ``_a2l_clamp_page_start`` and window bounds.
            - Build 16-cell tuples with the same fields the prior renderer produced,
              wrap each cell in a severity-styled ``rich.text.Text``, and insert
              via per-row ``add_row`` with ``a2l:<absolute_index>`` keys.

        Dependencies:
            Uses:
                - ``_a2l_clamp_page_start`` / ``_get_window_bounds``
                - ``_a2l_tag_row_severity`` / ``_severity_style``
                - ``_a2l_tag_in_memory_display`` / ``_a2l_tag_unit_display``
            Used by:
                - ``_refresh_a2l_filtered_tags``
                - ``update_a2l_view``
                - A2L tag paging and find actions
        """
        populate_started = time.perf_counter()
        a2l_table = self.query_one("#a2l_tags_list", DataTable)
        summary_label = self.query_one("#a2l_tags_summary", Label)
        self._a2l_row_key_to_tag = {}
        a2l_table.clear(columns=False)
        self._debug_log(
            run_id="initial",
            hypothesis_id="H3",
            location="s19_app/tui/app.py:update_a2l_tags_view",
            message="Entered update_a2l_tags_view",
            data={"incoming_tag_count": len(tags)},
        )
        if not tags:
            self._a2l_window_start = 0
            summary_label.update("No A2L tags.")
            self.logger.info(
                "Load phase boundary: populate_a2l_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        total_tags = len(tags)
        self._a2l_window_start = self._a2l_clamp_page_start(total_tags)
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        start, end = self._get_window_bounds(total_tags, self._a2l_window_start, page_size)
        self._a2l_window_start = start
        visible_tags = tags[start:end]
        for i, tag in enumerate(visible_tags):
            absolute_index = start + i
            row_key = f"a2l:{absolute_index}"
            self._a2l_row_key_to_tag[row_key] = tag
            cells = self._build_a2l_table_cells(tag)
            severity = _a2l_tag_row_severity(tag)
            style = _severity_style(severity)
            rich_cells = tuple(Text(cell, style=style) if style else Text(cell) for cell in cells)
            try:
                a2l_table.add_row(*rich_cells, key=row_key)
            except Exception:
                a2l_table.add_row(*rich_cells)
        page_num = start // page_size + 1
        total_pages = max(1, (total_tags + page_size - 1) // page_size)
        summary_label.update(
            f"Page {page_num}/{total_pages} | tags {start + 1}-{end} / {total_tags} "
            f"(page size {page_size}; +/- to change page)"
        )
        self._debug_log(
            run_id="initial",
            hypothesis_id="H3",
            location="s19_app/tui/app.py:update_a2l_tags_view",
            message="Finished update_a2l_tags_view",
            data={"rendered_tag_rows": len(visible_tags), "total_rows": total_tags, "start": start, "end": end},
        )
        self.logger.info(
            "Load phase boundary: populate_a2l_table_done rows=%d total=%d elapsed=%.3f",
            len(visible_tags),
            total_tags,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _build_a2l_table_cells(self, tag: dict) -> tuple[str, ...]:
        """
        Summary:
            Project one enriched A2L tag into the 16-cell tuple the DataTable row
            expects, keeping every field the previous ListView renderer surfaced.

        Args:
            tag (dict): Enriched A2L tag with value, memory, and schema fields.

        Returns:
            tuple[str, ...]: 16-string tuple aligned with the DataTable columns.

        Data Flow:
            - Format address/length/limits defensively so missing fields stay blank.
            - Reuse ``_a2l_tag_in_memory_display`` / ``_a2l_tag_unit_display`` helpers
              so display conventions remain centralized.

        Dependencies:
            Uses:
                - ``_a2l_tag_in_memory_display``
                - ``_a2l_tag_unit_display``
            Used by:
                - ``update_a2l_tags_view``
        """
        addr = tag.get("address")
        length = tag.get("length")
        addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
        len_text = str(length) if isinstance(length, int) else "n/a"
        name_text = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
        source_text = str(tag.get("source") or "assigned")
        raw_value_text = str(tag.get("raw_value") if tag.get("raw_value") is not None else "")
        physical_value_text = str(
            tag.get("physical_value") if tag.get("physical_value") is not None else ""
        )
        in_mem_text = _a2l_tag_in_memory_display(tag)
        region_text = str(tag.get("memory_region") or "unknown")
        limits_text = ""
        if tag.get("lower_limit") is not None or tag.get("upper_limit") is not None:
            limits_text = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
        unit_text = _a2l_tag_unit_display(tag)
        bit_text = str(tag.get("bit_org") or "")
        endian_text = str(tag.get("endian") or "")
        virt_text = "yes" if tag.get("virtual") else "no"
        func_text = str(tag.get("function_group") or "")
        access_text = str(tag.get("access") or "")
        dtype_text = str(tag.get("datatype") or "")
        return (
            name_text,
            addr_text,
            len_text,
            source_text,
            raw_value_text,
            physical_value_text,
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
                    str(tag.get("raw_value") or ""),
                    str(tag.get("physical_value") or ""),
                    _a2l_tag_in_memory_display(tag),
                    str(tag.get("lower_limit") or ""),
                    str(tag.get("upper_limit") or ""),
                    _a2l_tag_unit_display(tag),
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
        elif field == "raw_value":
            value = str(tag.get("raw_value") or "")
        elif field == "physical_value":
            value = str(tag.get("physical_value") or "")
        elif field == "in_memory":
            value = _a2l_tag_in_memory_display(tag)
        elif field == "limits":
            value = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
        elif field == "unit":
            value = _a2l_tag_unit_display(tag)
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

    def _toggle_settings_menu(self) -> None:
        """Show or hide the viewer settings dropdown menu."""
        menu = self.query_one("#settings_menu")
        if "hidden" in menu.classes:
            self._update_settings_menu()
            menu.remove_class("hidden")
        else:
            menu.add_class("hidden")

    def _update_settings_menu(self) -> None:
        """Populate settings menu rows with current viewer limits."""
        menu_list = self.query_one("#settings_menu_list", ListView)
        menu_list.clear()
        menu_list.append(ListItem(Label("Viewer limits (max 200)")))
        menu_list.append(ListItem(Label("-" * 30)))
        target_rows = [
            ("hex_rows_page_size", "Hex rows"),
            ("a2l_tags_page_size", "A2L tags"),
            ("mac_records_page_size", "MAC rows"),
        ]
        for attr_name, label in target_rows:
            current = self._clamp_viewer_page_size(getattr(self, attr_name))
            for option in self.viewer_page_size_options:
                marker = "*" if option == current else " "
                item = ListItem(Label(f"[{marker}] {label}: {option}"))
                item.data = (attr_name, option)
                menu_list.append(item)

    def _apply_viewer_setting(self, setting_name: str, setting_value: int) -> None:
        """Apply a viewer page-size setting and refresh dependent views."""
        safe_value = self._clamp_viewer_page_size(setting_value)
        if setting_name == "hex_rows_page_size":
            self.hex_rows_page_size = safe_value
            self.update_hex_view()
            self.update_alt_hex_view()
            self.update_mac_hex_view()
        elif setting_name == "a2l_tags_page_size":
            self.a2l_tags_page_size = safe_value
            self._a2l_window_start = self._a2l_clamp_page_start(len(self._a2l_filtered_tags))
            self.update_a2l_tags_view(self._a2l_filtered_tags)
        elif setting_name == "mac_records_page_size":
            self.mac_records_page_size = safe_value
            total_records = len(self.current_file.mac_records or []) if self.current_file else 0
            self._mac_window_start = self._mac_clamp_page_start(total_records)
            self.update_mac_view()
        else:
            return
        self.set_status(f"Updated {setting_name} to {safe_value}.")
        self._update_settings_menu()

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
        """
        Summary:
            Refresh the project-name / A2L-filename context labels in the
            persistent command bar so the project context stays visible from
            every Direction B screen (LLR-011.3).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Formats the project name and A2L filename (or a "(none)"
              sentinel) and writes them into the command bar's context
              labels — the command bar is the canonical home since the old
              Status tile was dismantled in increment 7.
            - Multi-variant projects (LLR-005.5): when the variant set holds
              N > 1 variants, the project label reads
              ``«project»:«variant» (i/N)`` with ``i`` the 1-based index of
              the active variant; single-variant projects keep the plain
              project name (LLR-005.3 back-compat).

        Dependencies:
            Uses:
                - ``CommandBar.set_context_labels``
                - ``_variant_display_options``
            Used by:
                - Project / A2L load handlers
                - ``_sync_loaded_file_to_project`` (variant append)
        """
        project_name = self.current_project or "(none)"
        variant_set = self._variant_set
        if (
            self.current_project
            and variant_set is not None
            and len(variant_set.variants) > 1
            and variant_set.active_id is not None
        ):
            options = self._variant_display_options(variant_set)
            active_index = next(
                (
                    index
                    for index, variant in enumerate(variant_set.variants)
                    if variant.variant_id == variant_set.active_id
                ),
                0,
            )
            display = options[active_index][1]
            project_name = (
                f"{self.current_project}:{display} "
                f"({active_index + 1}/{len(variant_set.variants)})"
            )
        a2l_name = self.current_a2l_path.name if self.current_a2l_path else "(none)"
        self.query_one(CommandBar).set_context_labels(project_name, a2l_name)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # The Direction B restyle retires the `#view_bar` button bar
        # (view_hex/a2l/mac_button, settings_button) — rail items 1-3
        # supersede the view-toggle buttons (LLR-004.4 / A-07).
        if event.button.id == "search_button":
            self._handle_search()
        elif event.button.id == "goto_button":
            self._handle_goto()
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
        elif event.button.id == "a2l_page_prev_button":
            self.action_a2l_tags_page_prev()
        elif event.button.id == "a2l_page_next_button":
            self.action_a2l_tags_page_next()
        elif event.button.id == "mac_page_prev_button":
            self.action_mac_records_page_prev()
        elif event.button.id == "mac_page_next_button":
            self.action_mac_records_page_next()
        elif event.button.id == "issues_filter_all":
            self.validation_issue_filter_mode = "all"
            self._validation_issues_window_start = 0
            self.update_validation_issues_view()
        elif event.button.id == "issues_filter_error":
            self.validation_issue_filter_mode = "error"
            self._validation_issues_window_start = 0
            self.update_validation_issues_view()
        elif event.button.id == "issues_filter_warning":
            self.validation_issue_filter_mode = "warning"
            self._validation_issues_window_start = 0
            self.update_validation_issues_view()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "a2l_tags_filter_input":
            self.a2l_tags_filter_text = event.value.strip()
            self._schedule_a2l_filter_refresh()
        elif event.input.id == "a2l_tag_find_input":
            self._a2l_tag_find_last_index = -1

    def _first_visible_hex_address(self, view: str) -> Optional[int]:
        """
        Summary:
            Return the base address of the first row currently visible in the named
            hex view, or ``None`` when the view has no rendered rows.

        Args:
            view (str): One of ``"main"``, ``"alt"``, or ``"mac"``.

        Returns:
            Optional[int]: First-visible row-base address; ``None`` when unavailable.
        """
        if view == "main":
            if not self.current_file:
                return None
            row_bases = self.current_file.row_bases or []
            if not row_bases:
                return None
            index = self._hex_window_start
            if not isinstance(index, int) or index < 0 or index >= len(row_bases):
                return None
            return row_bases[index]
        if view == "alt":
            return self._alt_first_visible_address
        if view == "mac":
            return self._mac_first_visible_address
        return None

    def _handle_search(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("main")

        addr = find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_hex_view(addr)
        self.set_status(f"Found at 0x{addr:08X}")

    def _apply_goto(self, view: str, addr: int) -> bool:
        """
        Summary:
            Validate a parsed goto address against the current file's loaded ranges and,
            on a hit, record the per-view focus address that drives the hex-row marker.

        Args:
            view (str): One of ``"main"``, ``"alt"``, or ``"mac"`` — selects the
                ``_<view>_goto_focus_address`` field updated on a hit.
            addr (int): Parsed integer goto address.

        Returns:
            bool: True when ``addr`` lies inside a loaded range (focus address set);
            False when out of range (status emitted, focus field left unchanged).

        Data Flow:
            - Resolve the cached sorted range index via ``_get_range_index``.
            - On a membership miss, emit the ``Address 0x... not in loaded file.`` status
              and return False without mutating any focus field.
            - On a hit, set the matching ``_<view>_goto_focus_address`` and return True.

        Dependencies:
            Uses:
                - ``_get_range_index``
                - ``address_in_sorted_ranges``
                - ``set_status``
            Used by:
                - ``_handle_goto`` / ``_handle_goto_alt`` / ``_handle_goto_mac``
        """
        range_index = self._get_range_index(self.current_file)
        if not address_in_sorted_ranges(addr, range_index):
            self.set_status(f"Address 0x{addr:08X} not in loaded file.")
            return False
        if view == "main":
            self._goto_focus_address = addr
        elif view == "alt":
            self._alt_goto_focus_address = addr
        elif view == "mac":
            self._mac_goto_focus_address = addr
        return True

    def _handle_goto(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#goto_input", Input).value.strip()
        if not raw:
            self._goto_focus_address = None
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self._goto_focus_address = None
            self.set_status("Invalid address format.")
            return
        if not self._apply_goto("main", addr):
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
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._alt_goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("alt")

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
            self._alt_goto_focus_address = None
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self._alt_goto_focus_address = None
            self.set_status("Invalid address format.")
            return
        if not self._apply_goto("alt", addr):
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
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._mac_goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("mac")

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
            self._mac_goto_focus_address = None
            self.set_status("Goto address is empty.")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self._mac_goto_focus_address = None
            self.set_status("Invalid address format.")
            return
        if not self._apply_goto("mac", addr):
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
