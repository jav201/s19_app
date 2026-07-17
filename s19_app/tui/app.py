from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import Any, List, Mapping, Optional, Sequence, Tuple

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
    TextArea,
)
from rich.text import Text

from ..compare import DIFF_KIND_DOMAIN
from ..core import S19File
from ..hexfile import IntelHexFile
from .a2l_parse import parse_a2l_file
from .changes import STATUS_VERIFIED, VerifyResult
from .hexview import (
    address_in_sorted_ranges,
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
    ChangeSetJsonScreen,
    EntryJsonScreen,
    LegendScreen,
    LoadFileScreen,
    LoadProjectScreen,
    OperationsScreen,
    ReportViewerScreen,
    SaveProjectPayload,
    SaveProjectScreen,
    SelectVariantScreen,
    VariantHelpScreen,
)
from .screens_directionb import (
    AbDiffPanel,
    FlowBuilderPanel,
    CoverageStats,
    EmptyStatePanel,
    MemoryMapPanel,
    PatchEditorPanel,
    bytes_per_cell,
    cell_count_for_geometry,
    cell_status,
    coverage_stats,
    derive_image_span,
    safe_text,
    status_to_css_class,
)
from .color_policy import css_class_for_severity
from .entropy_style import band_style
from .insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    LABEL,
    RED,
    VALUE,
    YELLOW,
    human_bytes,
    microbar,
)
from .services.entropy_service import EntropyWindow
from .issues_view import GroupedIssuesPanel, IssueRow
from ..validation import ValidationIssue, ValidationReport, ValidationSeverity
from .services.a2l_service import enrich_tags_and_render
from .services.before_after_service import compose_before_after_report
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
from .services.report_addendum import DeclaredRegion
from .services.report_filter import (
    ReportFilterMatcher,
    parse_report_filter,
    read_report_filter_text,
    resolve_report_filter,
)
from .services.report_service import (
    EXECUTION_SCOPE_TO_REPORT_MODE,
    REPORT_SOURCE_DEFAULT,
    REPORT_SOURCE_MANIFEST,
    ReportOptions,
    generate_project_report,
    list_project_reports,
)
from .services.manifest_writer import (
    ManifestVerifyResult,
    MANIFEST_VERIFIED,
    verify_written_manifest,
    write_project_manifest,
)
from .services.validation_service import (
    build_mac_coverage_strip,
    build_validation_report,
)
from .services.variant_execution_service import (
    EXECUTION_SCOPES,
    PROJECT_MANIFEST_NAME,
    SCOPE_ACTIVE,
    VariantExecutionResult,
    execute_project_variants,
    read_project_manifest,
)
from .workspace import (
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    S19_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_PATCHES,
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
#: actions of increment E3a extended by ``execute_scope`` at E6 (the stated
#: F-A-15 extension, LLR-006.6) and by ``parse_paste`` at batch-13
#: (LLR-014.2 — the paste-changeset surface; ten total).
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
        "parse_paste",
        "refresh_doc",
    }
)


#: Upper bound on a synthesized S0 header payload (US-015 / LLR-015.2): the
#: S19 ``byte_count`` field is one byte, so the S0 data plus its 2-byte
#: address and 1-byte checksum cannot exceed 255 — leaving ≤252 data bytes.
#: ``emit_s19_from_mem_map`` enforces the same cap; this trims the synthesized
#: header before it ever reaches the emitter.
_SAVEBACK_S0_MAX_BYTES = 252


def _synth_s0_header_from_filename(filename: str) -> bytes:
    """
    Summary:
        Synthesize a minimal populated S0 header from a save-back destination
        filename (US-015 / LLR-015.2) — used in 32-byte mode when the loaded
        image carried no source S0 to preserve. The result is plain ASCII,
        bounded to ``_SAVEBACK_S0_MAX_BYTES`` so the emitter's one-byte
        ``byte_count`` field cannot overflow.

    Args:
        filename (str): The (possibly edited) operator-confirmed target name.

    Returns:
        bytes: The ASCII bytes of ``filename`` with any non-ASCII character
        dropped, truncated to ``_SAVEBACK_S0_MAX_BYTES``. May be empty when
        ``filename`` holds no ASCII characters — an empty header is a valid,
        inert S0 the emitter accepts.

    Data Flow:
        - Encode the name as ASCII dropping un-encodable characters, then
          truncate to the 252-byte cap; the emitter writes it verbatim as the
          S0 data field, inert to the memory map.

    Dependencies:
        Used by:
            - S19TuiApp.on_patch_editor_panel_save_back_decision
    """
    ascii_bytes = filename.encode("ascii", errors="ignore")
    return ascii_bytes[:_SAVEBACK_S0_MAX_BYTES]


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


_A2L_ISSUE_SEVERITY_RANK: dict[ValidationSeverity, int] = {
    ValidationSeverity.NEUTRAL: 0,
    ValidationSeverity.OK: 1,
    ValidationSeverity.INFO: 2,
    ValidationSeverity.WARNING: 3,
    ValidationSeverity.ERROR: 4,
}
"""Severity ordering for ``_a2l_issue_severity_map`` — ``ERROR`` ranks above all (LLR-037.1)."""


def _a2l_issue_severity_map(
    issues: list[ValidationIssue],
) -> dict[str, ValidationSeverity]:
    """
    Summary:
        Derive a casefolded symbol -> maximum-severity map from a validation
        issue list, restricted to issues with ``artifact == "a2l"`` and a
        non-empty symbol (LLR-037.1, US-033 issue-implies-red-row).

    Args:
        issues (list[ValidationIssue]): Current validation issue list
            (``S19TuiApp._validation_issues`` at render time).

    Returns:
        dict[str, ValidationSeverity]: Casefolded issue symbol -> highest
        severity observed for that symbol per ``_A2L_ISSUE_SEVERITY_RANK``
        (``ERROR`` above all).

    Raises:
        None

    Data Flow:
        - Skip issues whose ``artifact`` is not ``"a2l"`` or whose ``symbol``
          is empty/absent (symbol-less codes such as ``A2L_STRUCTURE_ERROR``
          never map).
        - Casefold each symbol so lookups match the engine's ``name.lower()``
          duplicate grouping (``validation/rules.py``).
        - Keep the maximum severity per symbol, order-independent.
        - Pure function: O(issues) build, no widget access; consulted O(1)
          per rendered row.

    Dependencies:
        Uses:
            - ``_A2L_ISSUE_SEVERITY_RANK``
        Used by:
            - ``S19TuiApp.update_a2l_tags_view`` (built once per render)

    Example:
        >>> dup = ValidationIssue(
        ...     code="A2L_DUPLICATE_SYMBOL",
        ...     severity=ValidationSeverity.ERROR,
        ...     message="dup",
        ...     artifact="a2l",
        ...     symbol="RPM",
        ... )
        >>> _a2l_issue_severity_map([dup])
        {'rpm': <ValidationSeverity.ERROR: 'error'>}
    """
    severity_map: dict[str, ValidationSeverity] = {}
    for issue in issues:
        if issue.artifact != "a2l" or not issue.symbol:
            continue
        key = issue.symbol.casefold()
        current = severity_map.get(key)
        if current is None or (
            _A2L_ISSUE_SEVERITY_RANK[issue.severity] > _A2L_ISSUE_SEVERITY_RANK[current]
        ):
            severity_map[key] = issue.severity
    return severity_map


def _a2l_tag_row_severity(
    tag: dict,
    issue_severity_map: Mapping[str, ValidationSeverity],
) -> ValidationSeverity:
    """
    Summary:
        Resolve the severity that colours one A2L table row: an ERROR-severity
        issue mapped to the tag's casefolded name wins; every other case keeps
        the pre-existing schema/memory ladder (LLR-037.2, US-033).

    Args:
        tag (dict): Enriched A2L tag dictionary.
        issue_severity_map (Mapping[str, ValidationSeverity]): Casefolded
            symbol -> max severity map from ``_a2l_issue_severity_map``; pass
            ``{}`` for the ladder-only behavior.

    Returns:
        ValidationSeverity: Row severity consumed by ``_severity_style``.

    Raises:
        None

    Data Flow:
        - Return ``ERROR`` when the tag's casefolded name maps to ``ERROR``.
          Only ERROR recolours — a WARNING-mapped symbol falls through
          unchanged, because the A2L palette is Red/Green/White/Grey only
          (orange is a MAC-view convention; design decision D-2).
        - Otherwise apply the unchanged ladder: ``schema_ok=False`` -> ERROR;
          memory-checked present -> OK; memory-checked absent -> INFO;
          virtual/formula -> INFO; else NEUTRAL.

    Dependencies:
        Uses:
            - none
        Used by:
            - ``S19TuiApp.update_a2l_tags_view``

    Example:
        >>> _a2l_tag_row_severity(
        ...     {"name": "RPM", "schema_ok": True},
        ...     {"rpm": ValidationSeverity.ERROR},
        ... )
        <ValidationSeverity.ERROR: 'error'>
    """
    name = str(tag.get("name") or "").strip()
    if name and issue_severity_map.get(name.casefold()) is ValidationSeverity.ERROR:
        return ValidationSeverity.ERROR
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


REPORT_FILTERS_DIR_NAME = "filters"
"""Project subdirectory scanned for report-filter files (batch-35 US-056,
LLR-056.1): ``<project_dir>/filters/*.json`` feeds the report-viewer
dropdown. Net-new name — no prior production use (probe 2026-07-10)."""


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
    mac_widths: Optional[tuple] = None
    mac_cell_rows: list = field(default_factory=list)
    mac_cell_styles: list = field(default_factory=list)


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
    """
    return _SEVERITY_TO_RICH_STYLE.get(severity, "")


#: Leading MAC status glyph + Rich style (batch-47, LLR-070.1). Derived from the
#: record's precomputed ``Status`` + ``InMem`` cells so the render layer never
#: re-runs validation. Per LLR-070.1 and the sev-* convention (green = memory-
#: checked + present): ``✗`` red = parse-error; ``⚠`` orange = parse-ok +
#: out-of-image (the existing MAC-warning orange); ``✓`` green = parse-ok +
#: in-image; ``·`` grey = NOT image-checked (MAC-only load / no address → the
#: "not yet checked" state — must NOT read as a green "verified present").
_MAC_GLYPH_PARSE_ERROR: tuple[str, str] = ("✗", "red")
_MAC_GLYPH_OUT_OF_IMAGE: tuple[str, str] = ("⚠", "orange3")
_MAC_GLYPH_IN_IMAGE: tuple[str, str] = ("✓", "green")
_MAC_GLYPH_UNCHECKED: tuple[str, str] = ("·", "grey50")


def _mac_status_glyph(status: str, in_mem: str) -> tuple[str, str]:
    """
    Summary:
        Return the ``(glyph, style)`` for a MAC row from its precomputed
        ``Status`` string and ``InMem`` cell (``"yes"``/``"no"``/``"n/a"``),
        per LLR-070.1. ``✓`` green is reserved for a memory-checked + present
        record; an un-image-checked record (MAC-only load, no primary) renders
        the grey ``·`` "not yet checked" cue, never a false green.

    Args:
        status (str): The row's ``Status`` column value (``"ERR_PARSE"`` etc.).
        in_mem (str): The row's ``InMem`` column value — ``"yes"`` (in image),
            ``"no"`` (out of image), or ``"n/a"`` (not image-checked).

    Returns:
        tuple[str, str]: ``(glyph, rich_style)`` — one of the four
        ``_MAC_GLYPH_*`` constants.
    """
    if status == "ERR_PARSE":
        return _MAC_GLYPH_PARSE_ERROR
    if in_mem == "no":
        return _MAC_GLYPH_OUT_OF_IMAGE
    if in_mem == "yes":
        return _MAC_GLYPH_IN_IMAGE
    return _MAC_GLYPH_UNCHECKED


#: Fixed cell budget for the Workspace per-range coverage micro-bar (LLR-042.7).
#: Small enough (<= the ~18 usable cols of the 22-wide ``#ws_left`` pane) that the
#: bar renders as an ADDED third line inside the range row without widening it.
SECTIONS_COVERAGE_BAR_WIDTH = 8

#: Fallback column count for the Workspace whole-image memory strip (LLR-042.8)
#: used only before the ``#ws_memstrip`` band has a measured content width (e.g.
#: a headless render before layout). It caps the mounted cell count so a hostile
#: huge image never mounts unbounded cells even pre-layout.
WORKSPACE_MEMSTRIP_DEFAULT_COLS = 76

#: Glyph painted in each memory-strip cell. A full block so the ``sev-*`` colour
#: fills the cell; composed via ``safe_text`` so the band stays markup-safe.
_STRIP_CELL_GLYPH = "█"

#: App-supplied gap glyph for an unmapped address window in the memory strip
#: (batch-47, LLR-067.2). NOT an entropy band glyph — ``entropy_style`` owns only
#: ``· ░ ▒ ▓``; this hatch marks the holes between mapped ranges.
_STRIP_GAP_GLYPH = "╱"

#: Placeholder shown in the A2L detail card before any tag is highlighted
#: (batch-47, LLR-069.1).
_A2L_CARD_HINT = "Highlight a tag to inspect its fields."


def _card_field(text: Text, label: str, value: object) -> None:
    """
    Summary:
        Append a ``label value`` line to an A2L detail-card ``Text``, skipping
        blank/absent values (batch-47, LLR-069.2). The label is a fixed,
        developer-supplied token (muted); the value is appended literally so a
        file-derived value can never be interpreted as Rich markup (C-17).

    Args:
        text (Text): The card ``Text`` being composed (mutated in place).
        label (str): Fixed field label (never file-derived).
        value (object): The field value; ``None``/empty-string lines are elided.

    Returns:
        None

    Data Flow:
        - Called by :func:`_a2l_detail_card_text` per optional field.
        - Uses ``Text.append`` (literal), never ``Text.from_markup``.

    Dependencies:
        Uses:
            - rich.text.Text ; LABEL ; VALUE
        Used by:
            - _a2l_detail_card_text
    """
    if value is None or value == "":
        return
    text.append("\n")
    text.append(f"{label} ", style=LABEL)
    text.append(str(value), style=VALUE)


def _a2l_detail_card_text(tag: Optional[dict]) -> Text:
    """
    Summary:
        Compose the A2L detail card as a single markup-safe Rich ``Text`` from a
        highlighted enriched tag: a header line (in-image glyph + name + cyan
        address) followed by the tag's description, unit·conversion, record
        layout, byte order, and limits (batch-47, LLR-069.2 / LLR-069.3). Every
        file-derived value is appended literally (``Text.append``), never
        f-strung into a markup string, so hostile bracket/link/ANSI/unbalanced
        input renders verbatim with no ``MarkupError`` (C-17).

    Args:
        tag (Optional[dict]): The highlighted enriched A2L tag, or ``None`` when
            no row is highlighted (renders the placeholder hint).

    Returns:
        Text: The composed card content. Never a ``str``; never markup-parsed.

    Data Flow:
        - ``None`` → a muted placeholder hint.
        - Otherwise header (glyph/name/address) + per-field lines via
          :func:`_card_field`; untrusted values appended literally.

    Dependencies:
        Uses:
            - rich.text.Text ; _card_field ; VALUE ; CYAN ; GREEN ; DGRAY ; LABEL
        Used by:
            - A2LDetailCard.show_tag
    """
    if not tag:
        return Text(_A2L_CARD_HINT, style=DGRAY)
    text = Text()
    in_mem = bool(tag.get("in_memory"))
    text.append("✓ " if in_mem else "· ", style=GREEN if in_mem else DGRAY)
    text.append(
        str(tag.get("display_identifier") or tag.get("name") or "UNKNOWN"),
        style=VALUE,
    )
    addr = tag.get("address")
    if isinstance(addr, int):
        text.append("  ")
        text.append(f"0x{addr:08X}", style=CYAN)
    _card_field(text, "desc", tag.get("description"))
    unit = tag.get("unit")
    conversion = tag.get("conversion")
    if unit or conversion:
        text.append("\n")
        text.append("unit ", style=LABEL)
        text.append(str(unit) if unit else "—", style=VALUE)
        if conversion:
            text.append(" · conv ", style=LABEL)
            text.append(str(conversion), style=VALUE)
    _card_field(text, "layout", tag.get("record_layout_name"))
    _card_field(text, "byteorder", tag.get("effective_byte_order"))
    lower = tag.get("lower_limit")
    upper = tag.get("upper_limit")
    if lower is not None or upper is not None:
        text.append("\n")
        text.append("limits ", style=LABEL)
        text.append(
            f"{lower if lower is not None else ''}..{upper if upper is not None else ''}",
            style=VALUE,
        )
    return text


class A2LDetailCard(Static):
    """
    Summary:
        A one-widget A2L detail card mounted at the top of ``#a2l_hex_pane``
        (batch-47, LLR-069.1). It renders the highlighted tag's hidden fields
        above the (shrunken) hex view in the same pane — no new pane. The card
        keeps a bounded height so the hex view below stays reachable at the
        80×24 floor (C-29); its content is a single markup-safe Rich ``Text``.

    Data Flow:
        - ``show_tag(tag)`` replaces the rendered content via
          :func:`_a2l_detail_card_text` (a markup-safe ``Text``).
        - Constructed with the placeholder hint so it renders before any
          highlight.

    Dependencies:
        Uses:
            - _a2l_detail_card_text
        Used by:
            - _compose_screen_a2l (mount) ; on_data_table_row_highlighted (update)

    Note (Textual internal-name shadowing): the only instance member added is
    the public ``show_tag`` method — no ``_nodes``/``_context`` (or any other
    ``Widget`` private) name is introduced, so mounting cannot silently deadlock.
    """

    DEFAULT_CSS = """
    A2LDetailCard {
        height: auto;
        max-height: 5;
        overflow-y: auto;
        padding: 0 1;
        border-bottom: solid $panel;
    }
    """

    def show_tag(self, tag: Optional[dict]) -> None:
        """
        Summary:
            Update the card to show ``tag``'s fields, or the placeholder hint
            when ``tag`` is ``None`` (batch-47, LLR-069.2).

        Args:
            tag (Optional[dict]): The highlighted enriched A2L tag, or ``None``.

        Returns:
            None

        Data Flow:
            - Delegates composition to :func:`_a2l_detail_card_text` and calls
              ``Static.update`` with the resulting ``Text``.

        Dependencies:
            Uses:
                - _a2l_detail_card_text
            Used by:
                - on_data_table_row_highlighted
        """
        self.update(_a2l_detail_card_text(tag))

#: Filled / empty glyphs for the range-magnitude micro-bar. Neither is a Rich
#: markup metacharacter, but the bar is composed into a ``rich.text.Text`` (never
#: a markup-parsed string) so the render surface stays markup-safe by construction.
def dominant_band_label(
    entropy_windows: Sequence[EntropyWindow], start: int, end: int
) -> Optional[str]:
    """
    Summary:
        Return the entropy band label covering the most bytes of the half-open
        address window ``[start, end)``, or ``None`` when no computed entropy
        window overlaps it (batch-47, LLR-066.2 / LLR-067.1). Pure arithmetic
        over the already-computed ``LoadedFile.entropy_windows`` — it recomputes
        no entropy.

    Args:
        entropy_windows (Sequence[EntropyWindow]): Loader-computed windows in
            ascending address order (``LoadedFile.entropy_windows``).
        start (int): Inclusive window start address.
        end (int): Exclusive window end address.

    Returns:
        Optional[str]: The band label with the greatest total overlapping byte
        span in ``[start, end)``; ``None`` when no window overlaps (empty
        windows or an all-gap window).

    Data Flow:
        - Accumulates overlap byte counts per band label, then returns the
          arg-max; ties resolve to the first band reaching the max (dict
          insertion order over the ascending-address windows).
        - Called by ``update_sections`` (per range row) and
          ``update_memory_strip`` (per strip cell) to pick a cell's band glyph.

    Dependencies:
        Uses:
            - EntropyWindow (read-only)
        Used by:
            - ``S19TuiApp.update_sections``
            - ``S19TuiApp.update_memory_strip``

    Example:
        >>> from s19_app.tui.services.entropy_service import EntropyWindow
        >>> w = EntropyWindow(0x0, 0x100, 256, 0.0, "constant/padding", False)
        >>> dominant_band_label([w], 0x0, 0x80)
        'constant/padding'
        >>> dominant_band_label([w], 0x200, 0x280) is None
        True
    """
    totals: dict[str, int] = {}
    for window in entropy_windows:
        lo = max(start, window.start)
        hi = min(end, window.end)
        if hi > lo:
            totals[window.band] = totals.get(window.band, 0) + (hi - lo)
    if not totals:
        return None
    return max(totals, key=lambda label: totals[label])


def build_loader_facts_text(
    error_count: int, ooo_count: int, entry_point: Optional[int]
) -> Text:
    """
    Summary:
        Compose the Workspace loader-facts line
        ``Loader N err · ⚠K OOO · Entry <hex-or-—>`` as a markup-safe
        ``rich.text.Text`` (batch-47, LLR-066.4 / LLR-066.6). Carries only
        numeric counts and a formatted hex entry address — never any
        file-derived free text — so the line is C-17-inert by construction.

    Args:
        error_count (int): ``len(LoadedFile.errors)`` — loader-level error count.
        ooo_count (int): ``LoadedFile.out_of_order_count`` — non-monotonic S19
            data-record count.
        entry_point (Optional[int]): ``LoadedFile.entry_point`` — the S7/S8/S9
            terminator address. A present-but-zero entry (``0x0``) renders
            ``Entry 0x00000000`` (PRESENT); ``None`` renders ``Entry —``
            (ABSENT, e.g. every HEX load).

    Returns:
        Text: The single loader-facts line, styled (err red when non-zero, OOO
        yellow when non-zero, entry cyan). Never a ``str``; never markup-parsed.

    Data Flow:
        - Pure formatting of already-derived scalars; appended by
          ``update_workspace_stats`` under the coverage-stats block in
          ``#ws_stats``.

    Dependencies:
        Uses:
            - rich.text.Text ; CYAN ; RED ; VALUE ; YELLOW
        Used by:
            - ``S19TuiApp.update_workspace_stats``
            - (test) AT-066a/AT-066b/AT-066c/AT-066d over ``#ws_stats``

    Example:
        >>> build_loader_facts_text(0, 4, 0x0).plain
        'Loader 0 err · ⚠4 OOO · Entry 0x00000000'
        >>> build_loader_facts_text(0, 0, None).plain
        'Loader 0 err · ⚠0 OOO · Entry —'
    """
    entry = f"0x{entry_point:08X}" if entry_point is not None else "—"
    text = Text()
    text.append("Loader ")
    text.append(f"{error_count} err", style=RED if error_count else VALUE)
    text.append(" · ")
    text.append(f"⚠{ooo_count} OOO", style=YELLOW if ooo_count else VALUE)
    text.append(" · ")
    text.append("Entry ")
    text.append(entry, style=CYAN)
    return text


def build_workspace_stats_text(
    stats: CoverageStats, error_count: int, warning_count: int
) -> Text:
    """
    Summary:
        Assemble the markup-safe Workspace stat pane body (LLR-042.9): coverage
        percent + range count (from ``coverage_stats``) and error / warning
        counts (severity tallies over ``_validation_issues``). No entropy figure
        (D3 descoped). Pure formatting of already-computed values.

    Args:
        stats (CoverageStats): Metrics from ``coverage_stats`` over the parsed
            ranges / validity and the pre-computed issue list.
        error_count (int): Count of ``ERROR``-severity validation issues.
        warning_count (int): Count of ``WARNING``-severity validation issues.

    Returns:
        Text: Four labelled lines. When there are no ranges the coverage line
        shows a neutral ``—`` (em dash) instead of ``0.00%``.

    Data Flow:
        - Called by ``S19TuiApp.update_workspace_stats``; rendered into
          ``#ws_stats``.

    Dependencies:
        Used by:
            - ``S19TuiApp.update_workspace_stats``
            - (test) TC-042.9
    """
    range_count = stats.valid_count + stats.invalid_count
    text = Text()
    if range_count == 0:
        text.append("Coverage: —\n")
    else:
        text.append(f"Coverage: {stats.coverage_pct:.2f}%\n")
    text.append(f"Ranges: {range_count}\n")
    text.append(f"Errors: {error_count}\n")
    text.append(f"Warnings: {warning_count}")
    return text


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
        Binding("x", "operations_view", "Operations", show=True),
        Binding("k", "show_legend", "Legend", show=True),
        Binding("b", "before_after_report", "Before/After report", show=False),
        Binding("1", "show_screen('workspace')", "Workspace", show=False),
        Binding("2", "show_screen('a2l')", "A2L Explorer", show=False),
        Binding("3", "show_screen('mac')", "MAC View", show=False),
        Binding("4", "show_screen('map')", "Memory Map", show=False),
        Binding("5", "show_screen('issues')", "Issues Report", show=False),
        Binding("6", "show_screen('patch')", "Patch Editor", show=False),
        Binding("7", "show_screen('diff')", "A2B Diff", show=False),
        Binding("8", "show_screen('flow')", "Flow Builder", show=False),
        ("plus", "page_next_context", "Page+"),
        ("minus", "page_prev_context", "Page-"),
        ("comma", "hex_page_prev", "Hex-"),
        ("period", "hex_page_next", "Hex+"),
        # batch-31 AC-3 (B-04): PgUp/PgDn were advertised by the Issues
        # panel's truncation note but had no binding anywhere. They route
        # through the issues-aware context actions (Issues screen pages the
        # grouped panel; A2L/MAC keep their +/- paging parity).
        Binding("pagedown", "page_down_context", "Page+", show=False),
        Binding("pageup", "page_up_context", "Page-", show=False),
        # batch-40 S2 (US-068a discoverability): ctrl+z / ctrl+y reach the
        # patch-editor change-set undo/redo without scrolling to the buttons.
        # The actions self-guard (patch screen active + A-01 source_path None),
        # so a press on any other screen / file-backed doc is a safe no-op.
        Binding("ctrl+z", "patch_undo", "Undo", show=False),
        Binding("ctrl+y", "patch_redo", "Redo", show=False),
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
        # Per-DataTable maps from visible row_key back to the underlying record so
        # the shared ``on_data_table_row_selected`` handler can jump correctly.
        self._mac_row_key_to_address: dict[str, int] = {}
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
        #: Monotonic image-load generation (batch-48 LLR-077.2). Bumped once
        #: per image install in ``_apply_prepared_load`` and pushed into
        #: ``_change_service``, which stamps it onto each check run so the
        #: Patch Editor's per-entry glyphs can never describe a PREVIOUS
        #: image: the service above is built once, here, and is never rebuilt
        #: on load, while a check run reads its ``actual_bytes`` from the
        #: image. ``0`` == no image loaded yet.
        self._image_generation: int = 0
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
        #: Declared memory regions captured from the Reports dialog when the
        #: operator presses Generate (HLR-027 capture, Option A). The single
        #: source of truth threaded into ``write_project_manifest`` on project
        #: SAVE so regions persist to ``project.json``. Empty ⇒ the manifest
        #: omits the ``declared_regions`` key (back-compat, byte-identical to
        #: the pre-batch-20 output).
        self._declared_regions: Tuple[DeclaredRegion, ...] = ()
        #: The sticky per-run report-filter selection (batch-35 B-07,
        #: LLR-056.3): the PATH of the operator-selected filter file, or
        #: ``None`` = full report. Stores only the path — never a parsed
        #: snapshot: the file is re-read, re-parsed, and re-resolved on the
        #: UI thread at every report trigger (D-9), so an edited file takes
        #: effect on the next run and a deleted/invalid file refuses
        #: (LLR-053.5). Consumed by ``_trigger_generate_report`` (Inc-3);
        #: the Inc-4 selector row writes it and ``action_before_after_report``
        #: joins as the second consumer.
        self._report_filter_path: Optional[Path] = None
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
              loaded image, and screen 8 (Flow Builder) composes + runs an
              ordered typed-block pipeline (R-TUI-059 tracer).
            - Screen 6 (Patch Editor) is the fully-wired v2 change flow —
              the ``PatchEditorPanel`` posts ``ActionRequested`` messages
              that ``app.py`` routes to ``ChangeService`` for
              load / validate / apply / save / run-checks (and batch-13 adds
              the ``parse_paste`` paste-changeset surface); screen 7
              (A2B Diff) is a static three-column placeholder (increment 10)
              that wires no diff logic.
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
                self._compose_screen_flow(),
                id="workspace_body",
            ),
            id="workspace_shell",
        )
        # Persistent status bar — the re-homed status text, progress bar and
        # log-tail labels that the old Workspace Status tile carried. Kept
        # above the footer so `set_status` / `set_file_status` / `set_progress`
        # / the log tail keep a stable target on every screen (increment 7).
        yield Container(
            # batch-39 (S3, C-17): #status_text renders FILE-DERIVED text — the
            # coexistence status embeds a verbatim `path.name`/`mac_path.name`
            # (`_format_coexistence_status`), so a hostile filename like
            # `[red]evil[/].s19` would leak styling or raise MarkupError.
            # markup=False at CONSTRUCTION persists across `.update()` (mirrors
            # the #log_line_* scrub below).
            Label("Ready.", id="status_text", markup=False),
            ProgressBar(total=100, id="progress_bar"),
            # batch-33 (LLR-051.8, C-17): the log lines render FILE-DERIVED
            # text (issue messages embedding verbatim {kind!r}/{fmt!r}/... ,
            # check reasons) — markup=False at CONSTRUCTION is the single
            # funnel scrub, applied AFTER the 50-char cap in
            # `_append_log_line` (never pre-escape: the cap would bisect
            # escape sequences). Closes the pre-existing CHG-KIND-UNKNOWN
            # class (five sibling messages). No caller uses intended markup
            # (repo-wide grep: zero Rich tags reach set_status).
            Label("", id="log_line_1", markup=False),
            Label("", id="log_line_2", markup=False),
            Label("", id="log_line_3", markup=False),
            Label("", id="log_line_4", markup=False),
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
            Container: ``#screen_workspace`` holding the ``#ws_memstrip``
            whole-image memory-strip band, ``#workspace_panes`` (the three-pane
            ``Horizontal``) and an ``EmptyStatePanel``. Visible at startup (no
            ``.hidden`` class).

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
            - Right context pane hosts the Workspace stat pane ``#ws_stats``
              (coverage %/range/error/warning counts, LLR-042.9) above
              ``#a2l_view`` (the A2L summary that ``update_a2l_view`` writes to).
            - The ``#ws_memstrip`` band above the panes is the render target of
              ``update_memory_strip`` — a single-row whole-image minimap
              (LLR-042.8); it spans the workspace body width so it does not
              steal the fixed ``#ws_left`` horizontal budget.
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
            Button("Load project (p)", id="ws_load_project_button"),
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
            Label("Coverage Stats", id="ws_stats_title"),
            Static("", id="ws_stats", markup=False),
            Label("Context", id="a2l_title"),
            ScrollableContainer(
                Static("", id="a2l_view", markup=False),
                id="a2l_scroll",
            ),
            id="ws_right",
            classes="db-pane",
        )
        # Pane border titles/subtitles — the dolphie-idiom insight chrome
        # (batch-47, LLR-066.1). Static labels; no file-derived text.
        _left_pane.border_title = "Workspace"
        _left_pane.border_subtitle = "sections"
        _center_pane.border_title = "Hex View"
        _center_pane.border_subtitle = "bytes"
        _right_pane.border_title = "Context"
        _right_pane.border_subtitle = "coverage"
        _panes = Horizontal(
            _left_pane,
            _center_pane,
            _right_pane,
            id="workspace_panes",
        )
        _memstrip = Container(id="ws_memstrip")
        return Container(
            _memstrip,
            _panes,
            EmptyStatePanel(),
            id="screen_workspace",
            classes="db-screen",
        )

    def _compose_screen_issues(self) -> Container:
        """
        Summary:
            Build the Direction B Issues Report rail screen (``#screen_issues``)
            as a dedicated full screen carrying the grouped validation Issues
            panel, its severity filter row and the summary line —
            promoted out of the old Workspace Status tile (LLR-011.1).

        Args:
            None

        Returns:
            Container: ``#screen_issues`` holding the filter row
            (``#validation_issues_filters``), an ``#issues_columns`` horizontal
            split whose left ``#issues_list_stack`` holds the grouped-dense
            ``GroupedIssuesPanel`` (``#validation_issues_groups``, the sole
            Issues surface since batch-29), beside a hex pane
            (``#issues_hex_pane``, US-020a), the ``#validation_issues_summary``
            label and an ``EmptyStatePanel``. Hidden at startup.

        Data Flow:
            - Lifts the ``#validation_issues_filters`` /
              ``#validation_issues_summary`` subtree intact out of the
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
                Button("Legend", id="issues_legend_button"),
                id="validation_issues_filters",
            ),
            Container(
                Container(
                    GroupedIssuesPanel(id="validation_issues_groups"),
                    id="issues_list_stack",
                ),
                Static("", id="issues_hex_pane", markup=False),
                id="issues_columns",
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

    def _compose_screen_flow(self) -> Container:
        """
        Summary:
            Build the rail-8 Flow Builder screen (``#screen_flow``, R-TUI-059)
            — the tracer surface hosting a :class:`FlowBuilderPanel`. Run is
            handled by ``on_flow_builder_panel_run_requested``.

        Args:
            None

        Returns:
            Container: ``#screen_flow`` holding a title label and the
            ``FlowBuilderPanel``. Hidden at startup.

        Data Flow:
            - Static composition. Activating the Flow rail item shows this
              container; Run posts ``FlowBuilderPanel.RunRequested``.

        Dependencies:
            Uses:
                - ``FlowBuilderPanel``
            Used by:
                - ``compose``
        """
        return Container(
            Label("Flow Builder", classes="db-screen-title"),
            FlowBuilderPanel(),
            id="screen_flow",
            classes="db-screen hidden",
        )

    def on_flow_builder_panel_run_requested(
        self, event: "FlowBuilderPanel.RunRequested"
    ) -> None:
        """Run the composed flow over the active project and paint the result.

        Summary:
            Handle the rail-8 Run (R-TUI-059): resolve the active project
            directory and execute the flow via the Textual-free
            ``flow_execution_service.run_flow`` (reads bounded to the project,
            writes to the work area — batch-44 security F1/F2), then hand the
            ``FlowRunResult`` back to the panel. A no-project state renders an
            error result instead of running. Runs synchronously — acceptable
            for the tracer's small images; a worker is deferred to polish.

        Args:
            event (FlowBuilderPanel.RunRequested): Carries the composed flow.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``flow_execution_service.run_flow``
            Used by:
                - ``FlowBuilderPanel`` Run button (message dispatch)
        """
        from .services.flow_execution_service import run_flow
        from .services.flow_model import (
            FLOW_STATUS_ERROR,
            FlowContext,
            FlowRunResult,
        )

        panel = self.query_one("#flow_panel", FlowBuilderPanel)
        project_dir = self._active_project_dir()
        if project_dir is None:
            panel.render_result(
                FlowRunResult(
                    status=FLOW_STATUS_ERROR,
                    diagnostics=["no project loaded - load a project first"],
                )
            )
            return
        result = run_flow(event.flow, FlowContext(project_dir=project_dir))
        panel.render_result(result)

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
            feed the shaped rows back to the screen — exactly the eleven
            ``PATCH_ACTIONS_V2`` actions (the LLR-003.2 eight plus the E6
            ``execute_scope`` extension, LLR-006.6, the batch-13
            ``parse_paste`` paste-changeset action, LLR-014.2, and the
            batch-37 ``refresh_doc`` re-read action, LLR-064a.1); a retired or
            unknown action is one status error, never a crash.

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
              re-validate the document; ``parse_paste`` replaces the owned
              document from the paste ``TextArea`` body via
              ``ChangeService.load_text`` (LLR-014.2), then the same apply
              path takes over; ``apply_doc`` runs the E2 engine
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
                # US-061 / LLR-061.1 clear-on-context: a new load resets
                # ChangeService.last_summary to None, so the persistent
                # before/after control's report input is gone — re-hide it.
                panel.hide_before_after_prompt()
                if not event.path_text.strip():
                    self.set_status(
                        "Patch Editor: enter a change-file path to load."
                    )
                else:
                    result = service.load(event.path_text, self.base_dir)
                    self._report_change_result(result)
            elif event.action == "parse_paste":
                panel.hide_before_after_prompt()  # LLR-061.1 clear-on-context
                result = service.load_text(event.paste_text)
                self._report_change_result(result)
            elif event.action == "refresh_doc":
                panel.hide_before_after_prompt()  # LLR-061.1 clear-on-context
                # US-064a / LLR-064a.1: re-read the CURRENTLY-LOADED document
                # from disk to reflect external edits. Source is the document's
                # own ``source_path`` (the file it was loaded from), NOT the
                # live ``#patch_doc_path_input`` value (A-03) — a post-load path
                # edit is "load", not "refresh". Reuses the validated
                # ``ChangeService.load`` seam (size-cap + resolve_input_path +
                # collect-don't-abort). A paste-authored / empty document has no
                # ``source_path`` → the existing load guard, not a crash.
                source_path = service.document.source_path
                if source_path is None:
                    self.set_status(
                        "Patch Editor: enter a change-file path to load."
                    )
                else:
                    result = service.load(str(source_path), self.base_dir)
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
                    if loaded.file_type in ("s19", "hex"):
                        suffix = ".hex" if loaded.file_type == "hex" else ".s19"
                        panel.show_save_prompt(f"{variant_id}-patched{suffix}")
                    else:
                        self.set_status(
                            f"{loaded.file_type} save-back not supported"
                        )
            elif event.action == "save_doc":
                self._report_change_result(service.save(self.base_dir))
                # R2 / LLR-030.3: a save while the patch screen is open must
                # appear in the dropdown without re-activation.
                self._prefill_patch_change_files()
            elif event.action == "run_checks":
                result = service.run_checks(
                    mem_map, loaded_ranges, mac_records, a2l_tags
                )
                self._report_change_result(result)
                panel.refresh_check_results(
                    service.check_rows(),
                    result.message,
                    service.check_aggregates(),
                )
            elif event.action == "execute_scope":
                self._trigger_execute_scope(event.scope_text or SCOPE_ACTIVE)
        except (ValueError, KeyError) as exc:
            self.set_status(f"Patch Editor: {exc}")

        panel.refresh_entries(service.rows(loaded_ranges))
        panel.refresh_issues(service.issue_lines())
        # US-064b / LLR-064b.4 A-01 guard: the JSON popup opens ONLY for a
        # paste-authored / empty document — disable Edit-JSON whenever the
        # document is file-backed (``source_path is not None``) so a stale
        # buffer can never Confirm-clobber a loaded document.
        panel.set_edit_json_enabled(service.document.source_path is None)
        # US-068a / LLR-068a.4 A-01 guard: undo/redo is available ONLY for a
        # paste-authored / empty document — disable both controls whenever the
        # document is file-backed so the history path cannot clobber it.
        panel.set_undo_redo_enabled(service.document.source_path is None)
        # US-068b / LLR-068b.4 A-01 guard: the per-entry JSON edit is available
        # ONLY for a paste-authored / empty document — disable it whenever the
        # document is file-backed so a per-entry edit cannot clobber it.
        panel.set_entry_edit_json_enabled(service.document.source_path is None)

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
            - Confirm → resolve the operator's selected record width and the
              matching S0 policy (US-015 / LLR-015.3): at 32 bytes/line
              PRESERVE the loaded image's ``source_s0_header`` when present,
              else SYNTHESIZE a minimal ASCII S0 from the destination filename
              (``_synth_s0_header_from_filename``). Note: an EMPTY source S0
              (zero-length ``bytes``) is falsy and so is treated as absent →
              synthesized, same as ``None`` (the ``source_s0_header or synth``
              semantics). At 16 bytes/line write the
              legacy empty S0 (``s0_header=None``). Then
              ``ChangeService.save_patched`` into the active project directory
              (work-area root when no project is active); the typed name
              passes the engine's F-S-01 sanitizer; the result and its
              findings surface on the status path. ``loaded.path`` rides the
              ``source_image_path`` kwarg — the LLR-038.2 B-2 provenance
              stamp the before/after composer checks for staleness. On a
              successful save, after the verify outcome surfaces, an
              information notify offers the before/after report action
              (key ``b`` — LLR-038.3).

        Dependencies:
            Uses:
                - ``ChangeService.save_patched``
                - ``_active_project_dir``
                - ``_synth_s0_header_from_filename``
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
        bytes_per_line = event.bytes_per_line
        if bytes_per_line == 32:
            s0_header = loaded.source_s0_header or _synth_s0_header_from_filename(
                event.filename
            )
        else:
            s0_header = None
        result = self._change_service.save_patched(
            loaded.mem_map,
            loaded.ranges,
            dest_dir,
            event.filename,
            source_kind=loaded.file_type,
            bytes_per_line=bytes_per_line,
            s0_header=s0_header,
            source_image_path=loaded.path,
        )
        self._report_change_result(result)
        if result.ok:
            self._surface_verify_result()
            # US-061 / LLR-061.1: reveal the PERSISTENT before/after-report
            # control (a durable widget, not a Toast) so the report stays
            # discoverable after the notify below would have timed out. It is
            # re-hidden on the next document load (clear-on-context).
            panel.show_before_after_prompt()
            # LLR-038.3 offer — AFTER _surface_verify_result so a
            # verify-mismatch error notice is never masked; a mismatch does
            # NOT suppress the offer (A-m2: the report is an honest
            # disk-to-disk comparison of what was actually written).
            self.notify(
                "Before/after report ready - press b to write it to the "
                "project reports directory (action: before_after_report).",
                title="Before/after report",
                severity="information",
            )

    def on_patch_editor_panel_before_after_report_requested(
        self, event: PatchEditorPanel.BeforeAfterReportRequested
    ) -> None:
        """
        Summary:
            Route the persistent report control's activation (US-061 /
            LLR-061.2) to the single existing before/after report writer.
            The control is a SECOND trigger onto ``action_before_after_report``
            — the same handler the ``b`` accelerator binds to — so both paths
            write the identical ``reports/*.md`` + ``*.html`` pair for the same
            ``last_summary`` + loaded image, and no report-writing code is
            duplicated.

        Args:
            event (PatchEditorPanel.BeforeAfterReportRequested): The
                payload-free activation message from the persistent control.

        Returns:
            None

        Data Flow:
            - Delegate wholesale to ``action_before_after_report`` (which owns
              precondition validation, filter resolution, and every refusal
              class); a stale click after a context change is safe-by-refusal
              there (no ``last_summary`` → diagnostic on the status line, 0
              files written).

        Dependencies:
            Uses:
                - ``action_before_after_report``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        self.action_before_after_report()

    def on_patch_editor_panel_variant_help_requested(
        self, event: PatchEditorPanel.VariantHelpRequested
    ) -> None:
        """
        Summary:
            Open the variant-selector help modal (:class:`VariantHelpScreen`)
            when the operator presses ``#patch_variant_info_button``
            (US-067 / LLR-067.2). A pure trigger: the message carries no
            payload and the modal is static discovery help, so this handler
            just pushes the screen — no variant-set access, no state read.

        Args:
            event (PatchEditorPanel.VariantHelpRequested): The payload-free
                info-button trigger.

        Returns:
            None

        Data Flow:
            - ``push_screen(VariantHelpScreen())``; the modal dismisses itself
              via its Close button (no result callback needed).

        Dependencies:
            Uses:
                - ``VariantHelpScreen``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        self.push_screen(VariantHelpScreen())

    def _refresh_patch_history_view(self) -> None:
        """
        Summary:
            Re-render the Patch Editor after a change-set history restore
            (US-068a) — the shared tail of :meth:`on_patch_editor_panel_undo_
            requested` / :meth:`on_patch_editor_panel_redo_requested`. Mirrors
            the entries/issues/enable-sync tail of the action handler so the
            entries table, declaration-fault area, and both A-01 disable guards
            reflect the restored document.

        Data Flow:
            - Read the loaded image's ranges (``None`` when no image), then
              ``refresh_entries`` / ``refresh_issues``, clear the stale Checks
              panel from the restored (now check-less) document
              (``refresh_check_results`` — ``undo``/``redo`` reset
              ``last_check_result`` so ``check_rows`` returns the cleared state,
              batch-40 S1), and re-sync the Edit-JSON + Undo/Redo enable state
              from the restored document's ``source_path`` (LLR-068a.4).

        Dependencies:
            Uses:
                - ``ChangeService.rows`` / ``issue_lines`` / ``check_rows``
                - ``PatchEditorPanel.refresh_entries`` / ``refresh_issues``
                  / ``refresh_check_results`` / ``set_edit_json_enabled``
                  / ``set_undo_redo_enabled``
            Used by:
                - ``on_patch_editor_panel_undo_requested`` / ``..._redo_requested``
        """
        service = self._change_service
        loaded = self.current_file
        loaded_ranges = loaded.ranges if loaded is not None else None
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.refresh_entries(service.rows(loaded_ranges))
        panel.refresh_issues(service.issue_lines())
        # batch-40 S1: a history move (undo/redo) restores a change-set whose
        # entries no longer match the pre-move check run, so the stale Checks
        # panel must not persist. ``undo``/``redo`` reset ``last_check_result``
        # → ``check_rows`` returns the cleared state; render it here.
        # batch-48 LLR-078.3: the pass/fail strip rides that SAME reset —
        # ``check_aggregates()`` reads all-zero once ``last_check_result`` is
        # None, so the strip clears in step with the rows. Omitting it here
        # (while the post-run site supplies it) would leave a stale count.
        panel.refresh_check_results(
            service.check_rows(), "", service.check_aggregates()
        )
        panel.set_edit_json_enabled(service.document.source_path is None)
        panel.set_undo_redo_enabled(service.document.source_path is None)
        panel.set_entry_edit_json_enabled(service.document.source_path is None)

    def on_patch_editor_panel_undo_requested(
        self, event: PatchEditorPanel.UndoRequested
    ) -> None:
        """
        Summary:
            Restore the immediately-prior change-set (US-068a / LLR-068a.2/.3):
            route the payload-free Undo button trigger through the shared
            :meth:`action_patch_undo` path (the same one the ``ctrl+z`` key
            binding drives). An empty undo history is a no-op inside the
            service, so this handler is crash-free even with no history. The
            Undo control is disabled for a file-backed document (LLR-068a.4),
            so this message is only posted for a paste-authored / empty
            document.

        Args:
            event (PatchEditorPanel.UndoRequested): The payload-free trigger.

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_patch_undo`` (the shared guarded undo path)
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        self.action_patch_undo()

    def on_patch_editor_panel_redo_requested(
        self, event: PatchEditorPanel.RedoRequested
    ) -> None:
        """
        Summary:
            Re-apply the most-recently-undone change-set (US-068a /
            LLR-068a.2/.3): route the payload-free Redo button trigger through
            the shared :meth:`action_patch_redo` path (the same one the
            ``ctrl+y`` key binding drives). An empty redo stack is a
            service-level no-op.

        Args:
            event (PatchEditorPanel.RedoRequested): The payload-free trigger.

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_patch_redo`` (the shared guarded redo path)
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        self.action_patch_redo()

    def _patch_history_action_allowed(self) -> bool:
        """
        Summary:
            The A-01 guard shared by the ``ctrl+z`` / ``ctrl+y`` history key
            bindings (batch-40 S2): change-set undo/redo is reachable ONLY
            while the Patch Editor screen is active AND the owned document is
            paste-authored (``source_path is None``) — the exact enable-state
            :meth:`PatchEditorPanel.set_undo_redo_enabled` gives the Undo/Redo
            buttons. A key press on any other screen, or against a file-backed
            document, is a safe no-op so the binding can never bypass the
            LLR-068a.4 data-loss guard.

        Returns:
            bool: ``True`` when a history action may run (patch screen active
            and paste-authored document); ``False`` otherwise.

        Data Flow:
            - Read the ``#screen_patch`` container's ``hidden`` class (active
              iff not hidden), then the owned document's ``source_path``.

        Dependencies:
            Uses:
                - ``ChangeService.document``
            Used by:
                - ``action_patch_undo`` / ``action_patch_redo``
        """
        if self.query_one("#screen_patch").has_class("hidden"):
            return False
        return self._change_service.document.source_path is None

    def action_patch_undo(self) -> None:
        """
        Summary:
            Restore the immediately-prior change-set (US-068a / LLR-068a.2/.3),
            the shared body behind both the ``ctrl+z`` key binding and the
            ``#patch_undo_button`` trigger. Guarded by
            :meth:`_patch_history_action_allowed`, so it is a no-op unless the
            Patch Editor is active and the document is paste-authored (the
            A-01 guard); an empty undo history is itself a service-level no-op.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_patch_history_action_allowed``
                - ``ChangeService.undo`` / ``_refresh_patch_history_view``
            Used by:
                - The ``ctrl+z`` key binding
                - ``on_patch_editor_panel_undo_requested`` (the button path)
        """
        if not self._patch_history_action_allowed():
            return
        self._change_service.undo()
        self._refresh_patch_history_view()

    def action_patch_redo(self) -> None:
        """
        Summary:
            Re-apply the most-recently-undone change-set (US-068a /
            LLR-068a.2/.3), the shared body behind both the ``ctrl+y`` key
            binding and the ``#patch_redo_button`` trigger. Guarded by
            :meth:`_patch_history_action_allowed` (patch screen active +
            paste-authored A-01 guard); an empty redo stack is a service-level
            no-op.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_patch_history_action_allowed``
                - ``ChangeService.redo`` / ``_refresh_patch_history_view``
            Used by:
                - The ``ctrl+y`` key binding
                - ``on_patch_editor_panel_redo_requested`` (the button path)
        """
        if not self._patch_history_action_allowed():
            return
        self._change_service.redo()
        self._refresh_patch_history_view()

    def on_patch_editor_panel_edit_json_requested(
        self, event: PatchEditorPanel.EditJsonRequested
    ) -> None:
        """
        Summary:
            Open the full-size JSON popup (:class:`ChangeSetJsonScreen`) over
            the paste buffer (US-064b / LLR-064b.1), seeded from the message's
            ``paste_text``. Re-checks the LLR-064b.4 A-01 disable-guard
            defensively — even though ``#patch_edit_json_button`` is disabled
            for a file-backed document, this handler refuses to push the popup
            whenever ``ChangeService.document.source_path is not None`` so a
            stale-buffer Confirm can never ``load_text``-REPLACE (clobber) the
            loaded document. The popup's Confirm result is applied by
            :meth:`_apply_changeset_json_edit`.

        Args:
            event (PatchEditorPanel.EditJsonRequested): Carries the current
                ``#patch_paste_text`` buffer to seed the popup editor.

        Returns:
            None

        Data Flow:
            - ``source_path is not None`` → status-line refusal, no push
              (A-01 guard, LLR-064b.4).
            - else → ``push_screen(ChangeSetJsonScreen(seed),
              _apply_changeset_json_edit)``.

        Dependencies:
            Uses:
                - ``ChangeSetJsonScreen`` / ``_apply_changeset_json_edit``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._change_service.document.source_path is not None:
            self.set_status(
                "Patch Editor: Edit JSON is available only for a pasted "
                "change-set, not a file-loaded document."
            )
            return
        self.push_screen(
            ChangeSetJsonScreen(event.paste_text),
            self._apply_changeset_json_edit,
        )

    def _apply_changeset_json_edit(self, edited: Optional[str]) -> None:
        """
        Summary:
            Apply the JSON popup's Confirm result (US-064b / LLR-064b.2): write
            the edited text back to ``#patch_paste_text`` and route it through
            the EXISTING ``parse_paste`` → ``ChangeService.load_text`` seam by
            posting the panel's ``ActionRequested(parse_paste)`` — the SAME
            message the inline "Parse pasted" button posts — so no new
            parse/apply path is introduced and the collect-don't-abort
            re-render (entries table / issue lines / Edit-JSON enable-sync)
            happens through the one action handler. Cancel (``None``) is a
            no-op: the document and buffer are left unchanged.

        Args:
            edited (Optional[str]): The edited JSON on Confirm, or ``None`` on
                Cancel / Escape.

        Returns:
            None

        Data Flow:
            - ``None`` → return (Cancel; document unchanged).
            - else → set ``#patch_paste_text`` to ``edited`` and post
              ``PatchEditorPanel.ActionRequested(action="parse_paste",
              paste_text=edited)`` to re-use the existing paste apply arm.

        Dependencies:
            Uses:
                - ``PatchEditorPanel.ActionRequested`` / ``load_text`` seam
            Used by:
                - ``on_patch_editor_panel_edit_json_requested`` (push callback)
        """
        if edited is None:
            return
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        self.query_one("#patch_paste_text", TextArea).text = edited
        panel.post_message(
            PatchEditorPanel.ActionRequested(
                action="parse_paste", paste_text=edited
            )
        )

    def on_patch_editor_panel_entry_edit_json_requested(
        self, event: PatchEditorPanel.EntryEditJsonRequested
    ) -> None:
        """
        Summary:
            Open the per-entry JSON popup (:class:`EntryJsonScreen`) for the
            selected entry (US-068b / LLR-068b.1/.2), seeded with ONLY that
            entry's JSON via ``ChangeService.entry_seed_json`` — a single
            entry, distinct from the whole-set :class:`ChangeSetJsonScreen`.
            Re-checks the LLR-068b.4 A-01 disable-guard defensively — even
            though ``#patch_entry_edit_json_button`` is disabled for a
            file-backed document, this handler refuses to push the popup
            whenever ``source_path is not None`` so a stale index can never
            mutate a loaded document. Bounds-checks the index (a stale message
            after a shrink is a no-op). The popup's Confirm result is applied
            by :meth:`_apply_entry_json_edit` for the same index.

        Args:
            event (PatchEditorPanel.EntryEditJsonRequested): Carries the
                selected entries-table row index.

        Returns:
            None

        Data Flow:
            - ``source_path is not None`` → status-line refusal, no push
              (A-01 guard, LLR-068b.4).
            - index out of range → no-op.
            - else → ``push_screen(EntryJsonScreen(seed), callback)`` where the
              callback binds the index for :meth:`_apply_entry_json_edit`.

        Dependencies:
            Uses:
                - ``ChangeService.entry_seed_json`` / ``EntryJsonScreen``
                - ``_apply_entry_json_edit``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        service = self._change_service
        if service.document.source_path is not None:
            self.set_status(
                "Patch Editor: per-entry Edit JSON is available only for a "
                "pasted change-set, not a file-loaded document."
            )
            return
        if event.index < 0 or event.index >= len(service.document.entries):
            return
        seed = service.entry_seed_json(event.index)
        self.push_screen(
            EntryJsonScreen(seed),
            lambda edited, index=event.index: self._apply_entry_json_edit(
                index, edited
            ),
        )

    def _apply_entry_json_edit(
        self, index: int, edited: Optional[str]
    ) -> None:
        """
        Summary:
            Apply the per-entry JSON popup's Confirm result (US-068b /
            LLR-068b.3): route the edited single-entry text through
            ``ChangeService.edit_entry_json`` — which validates it via the
            EXISTING ``parse_change_document`` seam and replaces ONLY the
            selected entry (malformed input is collected, not applied) — then
            surface the result and re-render the entries table / issue lines /
            enable guards through the shared :meth:`_refresh_patch_history_view`
            tail. Cancel (``None``) is a no-op: the document is left unchanged.

        Args:
            index (int): The entry index the popup was opened for.
            edited (Optional[str]): The edited JSON on Confirm, or ``None`` on
                Cancel / Escape.

        Returns:
            None

        Data Flow:
            - ``None`` → return (Cancel; document unchanged).
            - else → ``edit_entry_json(index, edited)`` →
              ``_report_change_result`` → ``_refresh_patch_history_view``.

        Dependencies:
            Uses:
                - ``ChangeService.edit_entry_json`` / ``_report_change_result``
                - ``_refresh_patch_history_view``
            Used by:
                - ``on_patch_editor_panel_entry_edit_json_requested`` (callback)
        """
        if edited is None:
            return
        result = self._change_service.edit_entry_json(index, edited)
        self._report_change_result(result)
        self._refresh_patch_history_view()

    def _surface_verify_result(self) -> None:
        """
        Summary:
            Surface the verify-on-save outcome riding on
            ``ChangeService.last_summary.verify_result`` (HLR-004, hybrid
            D-B option 3): a quiet "saved + verified" status line on a clean
            verify (LLR-004.1), a prominent error notice naming the file and
            the per-kind run/byte mismatch summary on a ``mismatch``
            (LLR-004.2). The written file is left in place either way
            (collect-don't-abort) — surfacing only reads the already-computed
            ``VerifyResult``, it does not re-diff or re-verify.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Read ``last_summary.verify_result`` (the §6.2 C-10 carrier
              stamped by ``ChangeService.save_patched``); absent → no-op.
            - ``verified`` → one status line, no notice.
            - ``mismatch`` → one status line + a ``severity="error"`` notice
              built from ``stats.run_counts`` / ``byte_counts`` over
              ``DIFF_KIND_DOMAIN`` (counts/addresses only, never raw bytes —
              the F-S-05 no-byte-leak precedent).

        Dependencies:
            Uses:
                - set_status / notify
                - _verify_mismatch_summary
            Used by:
                - on_patch_editor_panel_save_back_decision
        """
        summary = self._change_service.last_summary
        if summary is None or summary.verify_result is None:
            return
        verify = summary.verify_result
        name = (
            verify.written_path.name
            if verify.written_path is not None
            else "image"
        )
        if verify.status == STATUS_VERIFIED:
            self.set_status(f"Saved + verified: {name}")
            return
        detail = self._verify_mismatch_summary(verify)
        self.set_status(f"Verify MISMATCH: {name}")
        self.notify(
            f"{name}: {detail}",
            title="Verify mismatch - file may not match",
            severity="error",
            timeout=10.0,
            markup=False,
        )

    def action_before_after_report(self) -> None:
        """
        Summary:
            Write the before/after save-back report pair (LLR-038.3, key
            ``b``): invoke the LLR-038.2 composer over the current
            ``ChangeService.last_summary`` + loaded image and surface the
            written paths — or the refusal diagnostic — on the status line.
            Surfaced text carries paths and diagnostics ONLY, never entry
            byte content (LLR-038.5 / S-F5).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When ``self._report_filter_path`` is set (LLR-053.5/054.1,
              D-9), read + parse + resolve the filter HERE on the UI
              thread, at trigger time — any read/parse fault refuses with
              the kind-prefixed diagnostic through the markup-inert
              ``set_status`` funnel (LLR-053.6), the composer is NOT
              invoked, and ``<project>/reports/`` stays unchanged.
              Resolution consumes ``loaded.mac_records`` +
              ``_compute_a2l_enriched_tags()`` (the LLR-053.4 (c) record
              extents) and stamps the file's name as the matcher's
              ``source_name`` (mirrors ``_trigger_generate_report``).
            - Gather ``last_summary``, ``LoadedFile.path``, the active
              project dir, and the workarea root; the composer validates the
              five LLR-038.2 preconditions and every LLR-038.4 refusal class
              itself — this handler never pre-duplicates them.
            - ``written`` → one status line naming BOTH written paths.
            - refusal → one status line carrying the composer's diagnostics;
              no file was written, the app keeps running.

        Dependencies:
            Uses:
                - ``compose_before_after_report``
                - ``read_report_filter_text`` / ``parse_report_filter``
                - ``resolve_report_filter`` / ``_compute_a2l_enriched_tags``
                - ``_active_project_dir`` / ``set_status``
            Used by:
                - key binding ``b`` (BINDINGS) after the save-back offer
                  notify in ``on_patch_editor_panel_save_back_decision``
        """
        loaded = self.current_file
        report_filter: Optional[ReportFilterMatcher] = None
        filter_path = self._report_filter_path
        if filter_path is not None:
            text, errors = read_report_filter_text(
                str(filter_path), self.base_dir
            )
            parsed = None
            if not errors and text is not None:
                parsed, errors = parse_report_filter(text)
            if errors or parsed is None:
                self.set_status(
                    "Before/after report refused: " + "; ".join(errors)
                )
                return
            mac_records = loaded.mac_records if loaded is not None else None
            a2l_tags = self._compute_a2l_enriched_tags() or None
            report_filter = resolve_report_filter(
                parsed,
                a2l_tags,
                mac_records,
                source_name=filter_path.name,
            )
        result = compose_before_after_report(
            self._change_service.last_summary,
            loaded.path if loaded is not None else None,
            project_dir=self._active_project_dir(),
            workarea=self.workarea,
            report_filter=report_filter,
        )
        if result.written:
            self.set_status(
                f"Before/after report written: {result.md_path} "
                f"| {result.html_path}"
            )
            return
        self.set_status(
            "Before/after report refused: " + " ".join(result.diagnostics)
        )

    @staticmethod
    def _verify_mismatch_summary(verify: VerifyResult) -> str:
        """
        Summary:
            Render a one-line mismatch summary from an already-computed
            ``VerifyResult`` (LLR-004.2) — per-kind run and byte counts over
            the canonical ``DIFF_KIND_DOMAIN`` order. Pure rendering: it reads
            ``verify.stats`` only and never re-diffs (the diff was computed in
            the verify engine), and it emits counts/addresses only, never raw
            image bytes (F-S-05 no-byte-leak precedent).

        Args:
            verify (VerifyResult): The mismatch outcome to summarize.

        Returns:
            str: e.g. ``"changed 1 run / 1 byte, only_a 0 run / 0 byte, ..."``.

        Dependencies:
            Uses:
                - DIFF_KIND_DOMAIN
            Used by:
                - _surface_verify_result
        """
        stats = verify.stats
        parts = [
            f"{kind} {stats.run_counts.get(kind, 0)} run / "
            f"{stats.byte_counts.get(kind, 0)} byte"
            for kind in DIFF_KIND_DOMAIN
        ]
        return ", ".join(parts)

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
            - ``self._declared_regions`` (set on load, LLR-028.1) is threaded
              into the screen so the region TextArea pre-fills (LLR-028.2).

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``list_project_reports``
                - ``_declared_regions`` (LLR-028.2 seed source)
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
        # Report-filter selector inputs (batch-35 US-056): scan the
        # dropdown options and seed the reopen state from the sticky
        # selection (LLR-056.2 F-05(i)) — a filters/-resident selection
        # seeds the Select, a free-path selection seeds the path input.
        filter_names = tuple(self._scan_report_filter_files())
        filters_dir = self._report_filters_dir()
        selected = self._report_filter_path
        filter_select_value: Optional[str] = None
        filter_path_text = ""
        if selected is not None:
            if (
                filters_dir is not None
                and selected.parent == filters_dir
                and selected.name in filter_names
            ):
                filter_select_value = selected.name
            else:
                filter_path_text = str(selected)
        self.push_screen(
            ReportViewerScreen(
                project_name,
                reports,
                declared_regions=self._declared_regions,
                filter_names=filter_names,
                filter_select_value=filter_select_value,
                filter_path_text=filter_path_text,
            )
        )

    def on_report_viewer_screen_filter_selected(
        self, message: ReportViewerScreen.FilterSelected
    ) -> None:
        """
        Summary:
            Install a dropdown filter pick into the sticky app-level
            selection (LLR-056.3): store the PATH only (never a parsed
            snapshot — the file is re-read per report run) and confirm on
            the status line through the markup-inert ``set_status`` funnel
            (LLR-053.6, never ``notify()``/``set_file_status``).

        Args:
            message (ReportViewerScreen.FilterSelected): The picked bare
                name, or ``None`` for the blank (full-report) selection.

        Returns:
            None

        Data Flow:
            - ``None`` pick → reset to ``None`` + "none" confirmation;
              already-``None`` is a silent no-op (absorbs the mount echo
              of the reopen seeding).
            - Name pick → ``filters_dir / name``; an unchanged path is a
              silent no-op (the reopen-seed echo), otherwise store +
              confirm carrying the FILENAME within the Q-7 budget.

        Dependencies:
            Uses:
                - ``_report_filters_dir`` / ``_confirm_filter_selection``
            Used by:
                - ``ReportViewerScreen.on_select_changed`` (posted message)
        """
        if message.name is None:
            if self._report_filter_path is None:
                return
            self._report_filter_path = None
            self.set_status("Report filter: none (full report)")
            self.logger.info("Report filter cleared.")
            return
        filters_dir = self._report_filters_dir()
        if filters_dir is None:
            return
        candidate = filters_dir / message.name
        if self._report_filter_path == candidate:
            return
        self._report_filter_path = candidate
        self.logger.info("Report filter selected: %s", candidate)
        self._confirm_filter_selection(message.name)

    def on_report_viewer_screen_filter_path_typed(
        self, message: ReportViewerScreen.FilterPathTyped
    ) -> None:
        """
        Summary:
            Resolve a typed free filter path (LLR-056.4): route through
            ``resolve_input_path`` against the app base dir, refuse a
            missing / symlinked / non-file target with a named diagnostic
            (the ``_scan_patch_change_files`` read-path security fold), and
            install the resolved path into the sticky selection. An
            out-of-project path is ALLOWED (read-only input, S-F5).

        Args:
            message (ReportViewerScreen.FilterPathTyped): The raw typed
                path text (stripped, non-empty).

        Returns:
            None

        Data Flow:
            - unresolvable → "Filter path not found: ..." (fault token
              leads within the 50-char funnel, Q-7); symlink / non-file →
              their named refusals; the sticky selection is UNCHANGED on
              every refusal.
            - resolved file → store + confirmation carrying the filename.

        Dependencies:
            Uses:
                - ``resolve_input_path`` / ``_confirm_filter_selection``
            Used by:
                - ``ReportViewerScreen.on_input_submitted`` (posted message)
        """
        raw = message.raw
        resolved = resolve_input_path(Path(raw), self.base_dir)
        if resolved is None:
            self.set_status(f"Filter path not found: {raw}")
            self.logger.info("Report filter path not found: %s", raw)
            return
        if resolved.is_symlink():
            self.set_status(f"Filter path is a symlink - refused: {raw}")
            self.logger.warning("Report filter symlink refused: %s", raw)
            return
        if not resolved.is_file():
            self.set_status(f"Filter path is not a file: {raw}")
            self.logger.info("Report filter non-file refused: %s", raw)
            return
        self._report_filter_path = resolved
        self.logger.info("Report filter selected by path: %s", resolved)
        self._confirm_filter_selection(resolved.name)

    def _confirm_filter_selection(self, display: str) -> None:
        """
        Summary:
            Surface the selection confirmation carrying the filter
            FILENAME within the Q-7 status budget (LLR-053.6): the message
            fits the 50-char funnel, or leads with its token — the bare
            filename — when the framed form would trim it away. Flows
            exclusively through the markup-inert ``set_status`` funnel.

        Args:
            display (str): The selected filter file's display name.

        Returns:
            None

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``on_report_viewer_screen_filter_selected``
                - ``on_report_viewer_screen_filter_path_typed``
        """
        message = f"Report filter: {display}"
        if len(message) > 50:
            message = display
        self.set_status(message)

    def on_report_viewer_screen_generate_requested(
        self, message: ReportViewerScreen.GenerateRequested
    ) -> None:
        """
        Summary:
            Route the viewer's Generate request to the generation flow
            (LLR-008.5), capturing the declared regions into app state for
            project SAVE persistence first (LLR-027.2) — pure dispatch
            otherwise, no report logic here.

        Args:
            message (ReportViewerScreen.GenerateRequested): Carries the
                collected ``context_bytes`` and ``declared_regions``.

        Returns:
            None

        Data Flow:
            - Store ``tuple(message.declared_regions)`` into
              ``self._declared_regions`` (HLR-027 capture, Option A) so a
              later project SAVE persists them — captured ON Generate, so a
              region typed but never generated with is not persisted.
            - Then dispatch ``context_bytes`` + regions to the generator.

        Dependencies:
            Uses:
                - ``_trigger_generate_report``
            Used by:
                - ``ReportViewerScreen`` (bubbled message)
        """
        self._declared_regions = tuple(message.declared_regions)
        self._trigger_generate_report(
            message.context_bytes, message.declared_regions
        )

    def _trigger_generate_report(
        self,
        context_bytes: int,
        declared_regions: Sequence[DeclaredRegion] = (),
    ) -> None:
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
            - When ``self._report_filter_path`` is set (LLR-055.1, D-9),
              read + parse + resolve the filter HERE on the UI thread —
              BEFORE the worker starts: any read/parse fault refuses with
              the kind-prefixed diagnostic through the markup-inert
              ``set_status`` funnel (LLR-053.5/053.6 — never ``notify()``
              or ``set_file_status``), no worker is dispatched, and
              ``<project>/reports/`` stays unchanged (F-04: refusal
              precedes any variant execution). Resolution consumes
              ``loaded.mac_records`` + ``_compute_a2l_enriched_tags()``
              (the LLR-053.4 (c) record extents) and stamps the file's
              name as the matcher's ``source_name``.
            - A retained snapshot from a DIFFERENT project directory is
              stale and treated as absent.
            - Without a usable snapshot, the same manifest-or-loaded-file
              guard as ``_trigger_execute_scope`` decides whether an
              active-scope run is even possible; the worker then executes
              with ``capture_mem_maps=True`` and generates in one pass.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``read_project_manifest``
                - ``read_report_filter_text`` / ``parse_report_filter``
                - ``resolve_report_filter`` / ``_compute_a2l_enriched_tags``
                - ``_start_generate_report_worker``
            Used by:
                - ``on_report_viewer_screen_generate_requested``
        """
        project_dir = self._active_project_dir()
        variant_set = self._variant_set
        if project_dir is None or variant_set is None or not variant_set.variants:
            self.set_status("Report: no project variants - load a project first.")
            return
        report_filter: Optional[ReportFilterMatcher] = None
        filter_path = self._report_filter_path
        if filter_path is not None:
            text, errors = read_report_filter_text(
                str(filter_path), self.base_dir
            )
            parsed = None
            if not errors and text is not None:
                parsed, errors = parse_report_filter(text)
            if errors or parsed is None:
                self.set_status(
                    "Project report refused: " + "; ".join(errors)
                )
                return
            loaded = self.current_file
            mac_records = loaded.mac_records if loaded is not None else None
            a2l_tags = self._compute_a2l_enriched_tags() or None
            report_filter = resolve_report_filter(
                parsed,
                a2l_tags,
                mac_records,
                source_name=filter_path.name,
            )
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
            project_dir,
            variant_set,
            context_bytes,
            last,
            fallback_batch,
            tuple(declared_regions),
            report_filter,
        )

    @work(thread=True, exclusive=True, group="generate_report")
    def _start_generate_report_worker(
        self,
        project_dir: Path,
        variant_set: ProjectVariantSet,
        context_bytes: int,
        last: Optional[tuple[Path, str, str, List[VariantExecutionResult]]],
        fallback_batch: list[Path],
        declared_regions: Sequence[DeclaredRegion] = (),
        report_filter: Optional[ReportFilterMatcher] = None,
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
            report_filter (Optional[ReportFilterMatcher]): The RESOLVED
                report filter (LLR-055.1), captured and resolved on the UI
                thread by ``_trigger_generate_report`` and handed over as
                an immutable explicit argument — the worker reads NO
                app-level selection state (F-04 thread contract: no
                stale/torn read). ``None`` = full report.

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
                declared_regions=tuple(declared_regions),
                report_filter=report_filter,
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

    def _patches_dir(self) -> Path:
        """Return the dedicated patches folder path (``workarea/patches/``).

        Summary:
            Resolve the change-file dropdown's scan/containment root — the
            dedicated patches folder created by ``ensure_workarea`` (LLR-031.1).
            The single source of truth for both the discovery scan (LLR-030.3)
            and the read-path containment guard (F1), so the two never drift.

        Args:
            None

        Returns:
            Path: ``<base_dir>/.s19tool/workarea/patches``.

        Dependencies:
            Uses:
                - ``self.workarea`` / ``WORKAREA_PATCHES``
            Used by:
                - ``_scan_patch_change_files``
                - ``on_patch_editor_panel_change_file_selected``
        """
        return self.workarea / WORKAREA_PATCHES

    def _scan_patch_change_files(self) -> List[str]:
        """Discover the change files under the patches folder (LLR-030.3).

        Summary:
            Return the sorted bare names of every ``*.json`` change file in
            ``workarea/patches/``, feeding the dropdown (US-026). The scan is
            SORTED deterministically (F-Q2) so the AT can select by known
            filename rather than by filesystem order, and it applies the
            read-path security fold at discovery time (F1): a symlink entry is
            SKIPPED (never listed), closing the write-guarded / read-unguarded
            asymmetry of the typed-path load.

        Args:
            None

        Returns:
            List[str]: The sorted bare component names (``match.name``) of the
            non-symlink ``*.json`` files under the patches folder; an empty
            list when the folder is absent or holds no change file.

        Data Flow:
            - ``patches_dir.glob("*.json")`` → drop ``is_symlink`` matches →
              collect ``match.name`` → ``sorted``.
            - A missing folder yields no glob matches (empty list), never a
              raise.

        Dependencies:
            Uses:
                - ``_patches_dir``
            Used by:
                - ``_prefill_patch_change_files``

        Example:
            >>> app._scan_patch_change_files()
            ['changes-1.json', 'changes.json']
        """
        patches_dir = self._patches_dir()
        if not patches_dir.is_dir():
            return []
        names = [
            match.name
            for match in patches_dir.glob("*.json")
            if not match.is_symlink()
        ]
        return sorted(names)

    def _report_filters_dir(self) -> Optional[Path]:
        """Resolve the active project's report-filters directory (US-056).

        Summary:
            ``<project_dir>/filters`` for the active project, or ``None``
            when no project is active — the report-filter dropdown then
            simply has no options (LLR-056.1).

        Args:
            None

        Returns:
            Optional[Path]: The filters directory path (existence NOT
            checked — the scanner tolerates absence), or ``None`` without
            an active project.

        Data Flow:
            - ``_active_project_dir()`` → append ``REPORT_FILTERS_DIR_NAME``.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / REPORT_FILTERS_DIR_NAME
            Used by:
                - ``_scan_report_filter_files``
                - ``action_view_reports`` (reopen seeding)
                - ``on_report_viewer_screen_filter_selected``
        """
        project_dir = self._active_project_dir()
        if project_dir is None:
            return None
        return project_dir / REPORT_FILTERS_DIR_NAME

    def _scan_report_filter_files(self) -> List[str]:
        """Discover the report-filter files under filters/ (LLR-056.1).

        Summary:
            Return the sorted bare names of every ``*.json`` file in the
            active project's ``filters/`` directory, feeding the
            report-viewer dropdown (US-056). Mirrors
            ``_scan_patch_change_files``: SORTED deterministically, and a
            symlink entry is SKIPPED (never listed) — the read-path
            security fold at discovery time.

        Args:
            None

        Returns:
            List[str]: The sorted bare component names of the non-symlink
            ``*.json`` files; an empty list when no project is active or
            the directory is absent/empty.

        Data Flow:
            - ``filters_dir.glob("*.json")`` → drop ``is_symlink`` matches
              → collect ``match.name`` → ``sorted``.
            - A missing directory yields no glob matches, never a raise.

        Dependencies:
            Uses:
                - ``_report_filters_dir``
            Used by:
                - ``action_view_reports``

        Example:
            >>> app._scan_report_filter_files()
            ['cal-only.json', 'crc-regions.json']
        """
        filters_dir = self._report_filters_dir()
        if filters_dir is None or not filters_dir.is_dir():
            return []
        names = [
            match.name
            for match in filters_dir.glob("*.json")
            if not match.is_symlink()
        ]
        return sorted(names)

    def _prefill_patch_change_files(self) -> None:
        """Prefill the Patch Editor change-file dropdown from patches/ (US-026).

        Summary:
            Scan ``workarea/patches/`` and hand the sorted change-file names to
            ``PatchEditorPanel.set_change_files`` (LLR-030.3). Called on
            patch-screen activation AND after each ``save_doc`` (R2), so a file
            saved while the screen is open appears without re-activation. An
            empty folder yields an empty option set — the panel renders the
            blank placeholder without crashing (AT-030b).

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``_scan_patch_change_files`` → ``panel.set_change_files``.
            - A not-yet-mounted panel (headless unit path) is tolerated as a
              no-op, matching ``_apply_empty_state``.

        Dependencies:
            Uses:
                - ``_scan_patch_change_files``
                - ``PatchEditorPanel.set_change_files``
            Used by:
                - ``action_show_screen`` (patch activation)
                - ``on_patch_editor_panel_action_requested`` (after save_doc)
        """
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            return
        panel.set_change_files(self._scan_patch_change_files())

    def _refresh_patch_variant_select(self) -> None:
        """Re-evaluate the Patch Editor variant dropdown from app state (US-028).

        Summary:
            Populate ``Select#patch_variant_select`` from the active project's
            ``ProjectVariantSet`` (LLR-035.3): with N >= 2 variants, one
            ``(variant_id, variant_id)`` option per variant in model order
            with the value pre-selected to ``active_id``; with N < 2 or no
            project, ``set_variants([])`` leaves the blank placeholder with
            the control disabled (LLR-035.5, DoR Q1). Called on patch-screen
            activation and — via ``update_project_labels``, which every
            variant-set mutation site already funnels through — whenever the
            variant set or the active variant changes while the screen is
            shown (the F-3 trigger set). The repopulate's
            ``Changed(Select.NULL)`` + ``Changed(active_id)`` echo pair (F-4) is
            absorbed by the handler chain's short-circuits (LLR-035.4).

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``self._variant_set`` → ``(variant_id, variant_id)`` option
              pairs (mirrors ``_prefill_diff_variants``) →
              ``PatchEditorPanel.set_variants``.
            - A not-yet-mounted panel (headless unit path) is tolerated as a
              no-op, matching ``_prefill_patch_change_files``.

        Dependencies:
            Uses:
                - ``PatchEditorPanel.set_variants``
            Used by:
                - ``action_show_screen`` (patch activation)
                - ``update_project_labels`` (variant-set change trigger)
        """
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            return
        variant_set = self._variant_set
        if variant_set is None or len(variant_set.variants) < 2:
            panel.set_variants([])
            return
        options = [
            (variant.variant_id, variant.variant_id)
            for variant in variant_set.variants
        ]
        panel.set_variants(options, variant_set.active_id)

    def _variant_load_in_flight(self) -> bool:
        """Report whether a load is still in flight (LLR-035.7 race guard).

        Summary:
            True while a variant activation (or any load) has not finished
            installing: either ``_pending_variant_id`` is stamped but not yet
            consumed by ``_apply_prepared_load``, or a ``"load"``-group
            worker is still unfinished. The variant-dropdown handler
            suppresses new picks while this holds — the suppress-while-loading
            mechanism chosen for LLR-035.7 (security F2): it touches the
            shared load pipeline nowhere, so the modal path is demonstrably
            unaffected.

        Args:
            None

        Returns:
            bool: ``True`` when a pick must be suppressed.

        Data Flow:
            - ``self._pending_variant_id`` (stamped at dispatch, consumed on
              the main thread at apply) OR any unfinished worker in the
              ``"load"`` group of ``self.workers``.

        Dependencies:
            Uses:
                - ``self.workers`` (Textual ``WorkerManager``)
            Used by:
                - ``on_patch_editor_panel_variant_selected``
        """
        if self._pending_variant_id is not None:
            return True
        return any(
            worker.group == "load" and not worker.is_finished
            for worker in self.workers
        )

    def on_patch_editor_panel_variant_selected(
        self, event: PatchEditorPanel.VariantSelected
    ) -> None:
        """Route a Variant-pane dropdown pick to the activation pipeline (US-028).

        Summary:
            Hand the picked id wholesale to ``_handle_select_variant``
            (LLR-035.4) — reusing its guards (no set / unknown id / missing
            file) and its ``_pending_variant_id`` → ``load_from_path`` →
            ``_apply_prepared_load`` stamping without duplicating any of
            them. Two short-circuits fire no activation: a pick equal to the
            current ``active_id`` (absorbs the F-4 repopulate echo — no
            redundant reload loop), and a pick arriving while a prior load is
            still in flight (LLR-035.7 suppress-while-loading; the stale
            display value self-heals when the in-flight activation completes
            and LLR-035.3 re-syncs the dropdown).

        Args:
            event (PatchEditorPanel.VariantSelected): Carries the picked
                variant id (the panel already filtered the blank sentinel
                ``Select.NULL``).

        Returns:
            None

        Data Flow:
            - same-as-active → drop; ``_variant_load_in_flight`` → drop with
              a status line; else ``_handle_select_variant(variant_id)``.

        Dependencies:
            Uses:
                - ``_variant_load_in_flight`` / ``_handle_select_variant``
            Used by:
                - Textual message dispatch (the panel's ``VariantSelected``)
        """
        variant_set = self._variant_set
        if variant_set is not None and event.variant_id == variant_set.active_id:
            return
        if self._variant_load_in_flight():
            self.set_status(
                "Variant switch ignored - a load is already in progress."
            )
            self.logger.info(
                "Variant pick '%s' suppressed: load in flight (LLR-035.7).",
                event.variant_id,
            )
            return
        self._handle_select_variant(event.variant_id)

    def on_patch_editor_panel_change_file_selected(
        self, event: PatchEditorPanel.ChangeFileSelected
    ) -> None:
        """Load a dropdown-chosen change file through the existing load path.

        Summary:
            Re-resolve the operator's chosen filename under the patches folder
            and, once the F1 containment guard passes, route it through the
            SAME ``ChangeService.load`` seam the typed-path Load action uses
            (LLR-030.3) — so the picked file becomes the active change document
            (its entries table reflects it). No new load/parse surface is
            introduced; only the source of the path differs.

        Args:
            event (PatchEditorPanel.ChangeFileSelected): Carries the bare
                filename the operator selected.

        Returns:
            None

        Data Flow:
            - Build ``candidate = patches_dir / event.filename`` and re-resolve.
            - **F1 guard:** SKIP (status line, no load) when the resolved path
              is a symlink or does not lie inside ``patches_dir.resolve()`` —
              closing the read-path asymmetry (``resolve_input_path`` has only a
              size cap, no containment/symlink guard).
            - Otherwise call ``ChangeService.load`` on the resolved absolute
              path and surface the result (``_report_change_result``); refresh
              the entries table from the new document.

        Dependencies:
            Uses:
                - ``_patches_dir`` / ``ChangeService.load``
                - ``_report_change_result`` / ``PatchEditorPanel.refresh_entries``
            Used by:
                - Textual message dispatch (the panel's ``ChangeFileSelected``)
        """
        patches_dir = self._patches_dir().resolve()
        raw = self._patches_dir() / event.filename
        candidate = raw.resolve()
        if raw.is_symlink() or not candidate.is_relative_to(patches_dir):
            self.set_status(
                f"Patch Editor: change file {event.filename!r} is outside "
                "the patches folder — not loaded."
            )
            return
        service = self._change_service
        result = service.load(str(candidate), self.base_dir)
        self._report_change_result(result)
        loaded = self.current_file
        loaded_ranges = loaded.ranges if loaded is not None else None
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.refresh_entries(service.rows(loaded_ranges))
        panel.refresh_issues(service.issue_lines())
        # US-064b / LLR-064b.4 A-01 guard: a dropdown-picked file is file-backed
        # (``source_path is not None``) → disable Edit-JSON (no clobber path).
        panel.set_edit_json_enabled(service.document.source_path is None)
        # US-068a / LLR-068a.4 A-01 guard: same file-backed doc → disable
        # Undo/Redo so the history path cannot clobber it either.
        panel.set_undo_redo_enabled(service.document.source_path is None)
        # US-068b / LLR-068b.4 A-01 guard: same file-backed doc → disable the
        # per-entry JSON edit so it cannot clobber the loaded document either.
        panel.set_entry_edit_json_enabled(service.document.source_path is None)

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
        mem_map_a, mem_map_b, failed_sides = self._diff_load_maps(result)
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
        if failed_sides:
            panel.set_status(
                f"Compare failed: {', '.join(failed_sides)} loaded no image "
                "(file has content but no valid records).",
                "sev-error",
            )
        else:
            panel.set_status(
                f"Compared {result.image_a.label} vs {result.image_b.label}: "
                f"{len(result.runs)} runs.",
                "sev-ok",
            )
        self._diff_last_result = result

    def _diff_load_maps(self, result) -> tuple[dict, dict, list[str]]:
        """
        Summary:
            Re-load the two compared images' memory maps for the on-screen hex
            windows and the report (LLR-005.2 / LLR-005.4), and detect a
            per-side load failure so the caller can surface an honest
            diagnostic instead of a silent clean compare (LLR-016.1). The
            comparison service returns runs but not the maps; the panel and the
            report generator both need the raw bytes, so this re-parses by path
            through the existing headless loaders.

            A side is a load failure when its source file has content on disk
            yet re-parses to an empty memory map (every record rejected, the
            collect-don't-abort degenerate case the service does not refuse),
            or the re-parse raises for a non-empty source. A legitimately small
            but valid image maps ≥1 byte and is NOT a failure.

        Args:
            result (ComparisonResult): The completed comparison.

        Returns:
            tuple[dict, dict, list[str]]: ``(mem_map_a, mem_map_b,
            failed_sides)`` where the two maps feed the hex windows unchanged
            (an unreadable image still yields an empty map — non-fatal) and
            ``failed_sides`` carries the human label of each side that loaded no
            image, out-of-band from the maps tuple the report path consumes.

        Data Flow:
            - Re-parse each side's path through ``build_loaded_s19`` /
              ``build_loaded_hex``; a raised parse becomes an empty map.
            - A non-empty source path whose map is empty is appended to
              ``failed_sides`` by its ``image.label``.

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

        def _source_has_content(image) -> bool:
            if not image.path:
                return False
            try:
                return Path(image.path).stat().st_size > 0
            except OSError:
                return False

        mem_map_a = _load(result.image_a)
        mem_map_b = _load(result.image_b)
        failed_sides: list[str] = []
        for image, mem_map in ((result.image_a, mem_map_a), (result.image_b, mem_map_b)):
            if not mem_map and _source_has_content(image):
                failed_sides.append(image.label or str(image.path))
        return mem_map_a, mem_map_b, failed_sides

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

        US-038 polish (LLR-042.2): the tags pane carries the queryable
        ``density-compact`` class (tightened pane padding, mirroring the
        ``#workspace_body.density-compact`` precedent) and the DataTable renders
        with ``cell_padding=0`` for compact rows. The fixed column header is the
        Textual ``DataTable`` default (LLR-042.1, verify-not-build); no change to
        the tag enrichment / paging / per-row severity colouring.
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
            DataTable(
                id="a2l_tags_list",
                zebra_stripes=True,
                cursor_type="row",
                cell_padding=0,
            ),
            Label("", id="a2l_tags_summary"),
            id="a2l_tags_pane",
            classes="db-pane density-compact",
        )
        _hex_pane = Container(
            A2LDetailCard(
                _a2l_detail_card_text(None),
                id="a2l_detail_card",
                markup=False,
            ),
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
                Button("Legend", id="mac_legend_button"),
                id="mac_page_controls",
            ),
            # Always-visible MAC->S19 coverage strip above the records list
            # (batch-47, LLR-071.1/071.2). Numeric-only content → markup=False.
            Static("", id="mac_coverage_strip", markup=False),
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
        """
        Summary:
            Open the save dialog (HLR-017 / LLR-017.3). When re-saving an
            existing multi-variant project (variant set known + a project dir
            on disk), pass the variant ``(variant_id, display)`` pairs and the
            enumerated project-relative ``.json`` candidate files so the screen
            renders per-variant assignment rows; a brand-new project save (no
            variant set) gets the bare dialog and writes empty composition
            (D-NEWPROJ).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Build ``variants`` via ``_variant_display_options`` and
              ``candidate_files`` via ``_assignment_candidate_files`` only when
              ``_variant_set``/``current_project_dir`` are present.
            - Push ``SaveProjectScreen`` with ``_handle_save_dialog`` as the
              dismiss callback.

        Dependencies:
            Uses:
                - ``_variant_display_options`` / ``_assignment_candidate_files``
                - ``SaveProjectScreen`` / ``push_screen``
            Used by:
                - save-project keybinding / command palette entry
        """
        if not self.current_file and not self.current_a2l_path:
            self.logger.info("Save project action triggered with no loaded files.")
        elif self.current_file:
            self.logger.info("Save project action triggered for %s", self.current_file.path)
        else:
            self.logger.info("Save project action triggered with A2L only.")
        variants: list[tuple[str, str]] = []
        candidate_files: list[str] = []
        variant_set = self._variant_set
        if variant_set is not None and variant_set.variants:
            variants = self._variant_display_options(variant_set)
            candidate_files = self._assignment_candidate_files()
        self.push_screen(
            SaveProjectScreen(self.workarea, variants, candidate_files),
            self._handle_save_dialog,
        )

    def _assignment_candidate_files(self) -> list[str]:
        """
        Summary:
            Enumerate the project-relative ``.json`` change/check documents
            assignable at save time (D-SCOPING), restricted to the current
            project directory's work area and excluding ``project.json``
            itself (LLR-017.3).

        Args:
            None

        Returns:
            list[str]: Sorted project-relative ``.json`` filenames in the
            project dir, ``project.json`` excluded. Empty when no project dir
            is known (a brand-new save) — the screen then renders no
            assignment rows (D-NEWPROJ).

        Data Flow:
            - Glob ``current_project_dir`` for ``*.json``, drop
              ``PROJECT_MANIFEST_NAME``, return the bare filenames (the
              writer's ``_reject_unsafe_entry`` is the path-safety authority).

        Dependencies:
            Used by:
                - ``action_save_project``
        """
        project_dir = self.current_project_dir
        if project_dir is None or not project_dir.is_dir():
            return []
        names = [
            item.name
            for item in project_dir.glob("*.json")
            if item.is_file() and item.name != PROJECT_MANIFEST_NAME
        ]
        return sorted(names)

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
    #: Ordered Workspace, A2L, MAC, Map, Issues, Patch, Diff, Flow —
    #: the rail order of the keymap proposal (keys 1-8).
    SCREEN_CONTAINER_IDS = {
        "workspace": "screen_workspace",
        "a2l": "screen_a2l",
        "mac": "screen_mac",
        "map": "screen_map",
        "issues": "screen_issues",
        "patch": "screen_patch",
        "diff": "screen_diff",
        "flow": "screen_flow",
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
                ``patch`` / ``diff`` / ``flow``).

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
        elif screen_key == "patch":
            self._prefill_patch_change_files()
            self._refresh_patch_variant_select()

    def action_show_legend(self) -> None:
        """
        Summary:
            Open the read-only classification-legend modal (HLR-023). The
            single Legend surface shared by every colour-coded view: the
            ``k`` key binding (reachable from the A2L explorer, where the
            dense filter row has no geometry budget for a button — C-13)
            and the MAC / Issues "Legend" buttons all route here.

        Returns:
            None

        Data Flow:
            - Pushes a fresh :class:`LegendScreen`, which renders
              ``legend.LEGEND_TABLE`` and dismisses itself on Close.

        Dependencies:
            Uses:
                - ``LegendScreen``
            Used by:
                - The ``k`` key binding
                - ``on_button_pressed`` (the MAC / Issues Legend buttons)
        """
        self.push_screen(LegendScreen())

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

    def action_page_down_context(self) -> None:
        """
        Summary:
            Route PgDn to the visible pageable surface — the Issues grouped
            panel when the Issues screen is active, else the ``+`` context
            paging (A2L / MAC tables) (batch-31 AC-3 / B-04).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When ``#screen_issues`` is visible, forward to
              ``action_validation_issues_page_next``.
            - Otherwise forward to ``action_page_next_context`` so PgDn is a
              synonym of ``+`` on the A2L/MAC screens.

        Dependencies:
            Uses:
                - ``_is_layout_visible``
                - ``action_validation_issues_page_next``
                - ``action_page_next_context``
            Used by:
                - the ``pagedown`` key binding
        """
        if self._is_layout_visible("#screen_issues"):
            self.action_validation_issues_page_next()
        else:
            self.action_page_next_context()

    def action_page_up_context(self) -> None:
        """
        Summary:
            Route PgUp to the visible pageable surface — the Issues grouped
            panel when the Issues screen is active, else the ``-`` context
            paging (A2L / MAC tables) (batch-31 AC-3 / B-04).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When ``#screen_issues`` is visible, forward to
              ``action_validation_issues_page_prev``.
            - Otherwise forward to ``action_page_prev_context``.

        Dependencies:
            Uses:
                - ``_is_layout_visible``
                - ``action_validation_issues_page_prev``
                - ``action_page_prev_context``
            Used by:
                - the ``pageup`` key binding
        """
        if self._is_layout_visible("#screen_issues"):
            self.action_validation_issues_page_prev()
        else:
            self.action_page_prev_context()

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
        # F-09 (LLR-056.3): project CREATE/SAVE swaps the active project
        # without reloading a file (no ``_apply_prepared_load`` pass), so
        # the sticky report-filter selection resets here.
        self._report_filter_path = None
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
        self._write_and_verify_manifest(
            project_dir,
            batch=payload.batch,
            assignments=payload.assignments,
            declared_regions=self._declared_regions,
        )
        self.update_project_labels()
        self.refresh_files()

    def _write_and_verify_manifest(
        self,
        project_dir: Path,
        *,
        batch: Sequence[str] = (),
        assignments: Optional[Mapping[str, Sequence[str]]] = None,
        declared_regions: Sequence[DeclaredRegion] = (),
    ) -> None:
        """
        Summary:
            Persist the active project's ``project.json`` and verify-check the
            write, then surface the outcome (HLR-004 / LLR-004.1). After the
            file-copy save, serialize the current ``ProjectVariantSet`` (its
            ``active_variant`` selection) into the canonical manifest envelope,
            write it atomically into the contained work area, re-read it, and
            hand the :class:`ManifestVerifyResult` to
            :meth:`_surface_manifest_verify_result`. Orchestration-only — the
            serialize / write / verify logic lives in the headless
            ``manifest_writer`` service; this method only calls it and renders.

        Args:
            project_dir (Path): The just-saved project directory the manifest is
                written into (``project.json`` lands directly here).
            batch (Sequence[str]): Project-wide change/check files as
                project-relative path strings (HLR-017 / LLR-017.2). Threaded
                IDENTICALLY into the write and the verify so the verify intent
                matches the write intent (R1); defaults empty (zero-selection
                save, unchanged active-variant-only behavior).
            assignments (Optional[Mapping[str, Sequence[str]]]): Per-variant
                change/check files keyed by ``variant_id``; same project-relative
                strings, same identical threading into write + verify (R1).
                ``None`` ⇒ empty assignments.
            declared_regions (Sequence[DeclaredRegion]): Operator-declared
                memory regions captured on Generate (HLR-027). Forwarded into
                ``write_project_manifest`` ONLY — NOT into
                ``verify_written_manifest``, which re-reads the written file as
                the oracle (CARRY C-P3c). Empty ⇒ the serializer omits the key
                (back-compat).

        Returns:
            None

        Data Flow:
            - No ``_variant_set`` (an empty / failed save) → no manifest write.
            - ``write_project_manifest`` returns ``(None, issues)`` on a refused
              serialize or a containment / IO failure (collect-don't-abort);
              that is surfaced as an error notice, never raised.
            - ``declared_regions`` is threaded into the write only; the verify
              re-reads the written ``project.json`` as the oracle, so threading
              regions into verify would be a tautology (it would compare the
              file against an intent already derived from the same source).
            - On a successful write, ``verify_written_manifest`` re-reads the
              canonical ``project.json`` and the result is surfaced (quiet on
              verified, loud on mismatch).

        Dependencies:
            Uses:
                - write_project_manifest / verify_written_manifest
                - _surface_manifest_verify_result
            Used by:
                - _handle_save_dialog
        """
        variant_set = self._variant_set
        if variant_set is None:
            return
        written, issues = write_project_manifest(
            variant_set,
            project_dir,
            self.base_dir,
            batch=batch,
            assignments=assignments,
            declared_regions=declared_regions,
        )
        if written is None:
            detail = "; ".join(issue.message for issue in issues) or "unknown error"
            self.set_status("Manifest write failed")
            self.notify(
                detail,
                title="Manifest write failed - project.json not written",
                severity="error",
                timeout=10.0,
                markup=False,
            )
            self.logger.warning("Manifest write refused: %s", detail)
            return
        result = verify_written_manifest(
            project_dir,
            variant_set,
            project_dir,
            batch=batch,
            assignments=assignments,
        )
        self._surface_manifest_verify_result(result)

    def _surface_manifest_verify_result(
        self, result: ManifestVerifyResult
    ) -> None:
        """
        Summary:
            Surface a manifest verify-on-write outcome (LLR-004.2), mirroring
            the batch-10 ``_surface_verify_result`` quiet/loud shape: a concise
            "manifest verified" status line on success, and on mismatch a status
            line plus a prominent error notice naming the drifting key(s) and
            the re-read reader issue messages. Reader-issue messages are
            attacker-influenceable and ``notify`` parses Rich markup by default,
            so the notice is emitted with ``markup=False`` — the message renders
            literally and a crafted path cannot inject markup (C-17).

        Args:
            result (ManifestVerifyResult): The already-computed verify outcome
                (status / drift / issues / written_path).

        Returns:
            None

        Data Flow:
            - ``verified`` → one status line, no notice.
            - ``mismatch`` → one status line + a ``severity="error"`` notice
              built from the ``drift`` key names and the plain-text
              ``issue.message`` strings (no raw markup).

        Dependencies:
            Uses:
                - set_status / notify
            Used by:
                - _write_and_verify_manifest
        """
        if result.status == MANIFEST_VERIFIED:
            self.set_status("Project saved + manifest verified")
            return
        parts: list[str] = []
        if result.drift:
            parts.append("drift: " + ", ".join(result.drift))
        if result.issues:
            parts.extend(issue.message for issue in result.issues)
        detail = "; ".join(parts) or "manifest re-read did not match intent"
        self.set_status("Manifest verify MISMATCH")
        self.notify(
            detail,
            title="Manifest verify mismatch - project.json may be wrong",
            severity="error",
            timeout=10.0,
            markup=False,
        )
        self.logger.warning("Manifest verify mismatch: %s", detail)

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
        # LLR-028.1 — adopt the manifest's declared regions as app state so the
        # next Reports dialog seeds from them (HLR-028 capture); reset to empty
        # for a legacy/no-key project so a prior project's regions do not leak.
        self._declared_regions = (
            tuple(manifest.declared_regions) if manifest is not None else ()
        )
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
        # ``mac_records_list`` and ``a2l_tags_list`` are ``DataTable`` widgets;
        # selection for those IDs arrives via ``on_data_table_row_selected``
        # instead of this ListView handler.

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
            - A2L rows -> ``_jump_to_tag_by_data`` via the ``_a2l_row_key_to_tag`` map.
            - Issues rows are NOT dispatched here: since batch-29 the Issues
              surface is the ``GroupedIssuesPanel`` whose ``IssueRow.Selected``
              message is handled by ``on_issue_row_selected`` (no DataTable).

        Dependencies:
            Uses:
                - ``_jump_to_mac_address``
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
        if table_id == "a2l_tags_list":
            tag = self._a2l_row_key_to_tag.get(key_value)
            if isinstance(tag, dict):
                self._jump_to_tag_by_data(tag)
            return

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        """
        Summary:
            Update the A2L detail card as the ``#a2l_tags_list`` cursor moves
            (batch-47, LLR-069.2). Distinct from ``on_data_table_row_selected``
            (which JUMPS the hex view on enter/click): highlight fires on cursor
            move, giving live per-tag feedback in the card without changing the
            hex position.

        Args:
            event (DataTable.RowHighlighted): Event payload carrying
                ``data_table`` and ``row_key``.

        Returns:
            None

        Data Flow:
            - Ignore non-A2L tables.
            - Resolve the row_key to an enriched tag via ``_a2l_row_key_to_tag``.
            - Hand the tag (or ``None``) to the mounted ``A2LDetailCard``.

        Dependencies:
            Uses:
                - ``A2LDetailCard.show_tag``
            Used by:
                - Textual event dispatch for ``DataTable.RowHighlighted``
        """
        table = getattr(event, "data_table", None)
        table_id = getattr(table, "id", None) if table is not None else None
        if table_id != "a2l_tags_list":
            return
        row_key = getattr(event, "row_key", None)
        key_value = getattr(row_key, "value", row_key)
        tag = (
            self._a2l_row_key_to_tag.get(key_value)
            if isinstance(key_value, str)
            else None
        )
        try:
            card = self.query_one("#a2l_detail_card", A2LDetailCard)
        except Exception:
            return
        card.show_tag(tag if isinstance(tag, dict) else None)

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

    def _update_issues_hex_pane(self, address: Optional[int]) -> None:
        """Render the selected issue's address bytes in ``#issues_hex_pane`` (US-020a).

        Summary:
            On an Issues-table row selection, show a focused hex+ASCII window
            around the issue's ``address`` in the Issues screen's hex pane
            (``#issues_hex_pane``, LLR-020.2). When the issue carries no address
            (a cross-artifact issue) or no file is loaded, show a fixed
            placeholder and clear any bytes from a prior selection — never a
            stale render.

        Args:
            address (Optional[int]): The selected issue's address, or ``None``.

        Returns:
            None

        Data Flow:
            - No pane present (Issues screen not composed) → no-op.
            - ``address`` is ``None`` / no file → the placeholder string.
            - Else render a ±``context``-row window via ``render_hex_view_text``
              focused at ``address`` into the pane.

        Dependencies:
            Uses:
                - ``render_hex_view_text``
            Used by:
                - ``_jump_to_validation_issue_object``
        """
        # No mounted screen (e.g. a headless unit-test call to the jump path) ->
        # there is no DOM to query; skip the best-effort pane update.
        if not self.screen_stack:
            return
        matches = self.query("#issues_hex_pane")
        if not matches:
            return
        pane = matches.first(Static)
        if not isinstance(address, int) or not self.current_file:
            pane.update("(issue has no address — nothing to show)")
            return
        base = address - (address % 16)
        context_rows = 6
        low = max(0, base - 16 * context_rows)
        row_bases = list(range(low, base + 16 * (context_rows + 1), 16))
        pane.update(
            render_hex_view_text(self.current_file.mem_map, address, row_bases, None)
        )

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
                - ``_jump_to_validation_issue`` (legacy ListView adapter)
        """
        address = issue.address
        # US-020a: every issue selection refreshes the on-screen Issues hex pane
        # (bytes at the address, or a placeholder when the issue carries none).
        self._update_issues_hex_pane(address)
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
            Compute the aggregate validation-issue counts + paging summary line,
            push them into the ``#validation_issues_summary`` ``Label``, and
            render the grouped Issues view via ``_render_validation_issues_groups``.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Resolve the filtered list via ``_filtered_validation_issues``.
            - Short-circuit with a summary-only message when there are no issues
              (still re-rendering the grouped panel so it clears).
            - Compute aggregate counts (errors/warnings/info) and a page-number line.
            - Render the current paging window through
              ``_render_validation_issues_groups`` — the sole Issues surface
              since batch-29 retired the legacy Issues DataTable.

        Dependencies:
            Uses:
                - ``_filtered_validation_issues``
                - ``_clamp_viewer_page_size`` / ``_get_window_bounds``
                - ``_render_validation_issues_groups``
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
                - ``update_mac_view`` (when MAC/validation input changes)
                - issue filter buttons and paging actions
        """
        populate_started = time.perf_counter()
        summary_label = self.query_one("#validation_issues_summary", Label)
        filtered = self._filtered_validation_issues()
        if not filtered:
            summary_label.update("No validation issues.")
            self._render_validation_issues_groups()
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
        self._render_validation_issues_groups()
        self.logger.info(
            "Load phase boundary: populate_issues_table_done rows=%d total=%d elapsed=%.3f",
            end - start,
            total,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _render_validation_issues_groups(self) -> None:
        """
        Summary:
            Render the grouped-by-severity dense Issues view
            (``#validation_issues_groups``) — the sole Issues surface since
            batch-29 — from the current filtered list + paging window
            (US-039 / LLR-042.3/.4/.6). Groups render in error →
            warning → info order; each group-header count is the whole
            (filtered) list count for that severity, while only the current
            bounded paging window of rows is mounted — a hostile large-N issue
            list therefore cannot mount O(N) row widgets.

        Args:
            None

        Returns:
            None

        Data Flow:
            - No mounted screen (headless / monkeypatched unit call) or no
              grouped panel present → no-op.
            - Else resolve the filtered list, reuse ``_get_window_bounds`` /
              ``page_size`` for the window, tally per-severity whole-filtered
              counts, and hand them to ``GroupedIssuesPanel.render_groups``.

        Dependencies:
            Uses:
                - ``_filtered_validation_issues`` / ``_clamp_viewer_page_size``
                  / ``_get_window_bounds``
                - ``GroupedIssuesPanel.render_groups``
            Used by:
                - ``update_validation_issues_view``
        """
        if not self.screen_stack:
            return
        panels = self.query("#validation_issues_groups")
        if not panels:
            return
        panel = panels.first(GroupedIssuesPanel)
        filtered = self._filtered_validation_issues()
        if not filtered:
            panel.render_groups([], {}, truncated=False)
            return
        total = len(filtered)
        page_size = self._clamp_viewer_page_size(self.validation_issues_page_size)
        start, end = self._get_window_bounds(
            total, self._validation_issues_window_start, page_size
        )
        window = filtered[start:end]
        group_counts = {
            ValidationSeverity.ERROR: sum(
                1 for item in filtered if item.severity == ValidationSeverity.ERROR
            ),
            ValidationSeverity.WARNING: sum(
                1 for item in filtered if item.severity == ValidationSeverity.WARNING
            ),
            ValidationSeverity.INFO: sum(
                1 for item in filtered if item.severity == ValidationSeverity.INFO
            ),
        }
        panel.render_groups(window, group_counts, truncated=(end - start) < total)

    def on_issue_row_selected(self, event: "IssueRow.Selected") -> None:
        """
        Summary:
            Repaint the retained ``#issues_hex_pane`` when an issue row in the
            grouped view is activated by a real click or ``Enter`` (LLR-042.5,
            C-16 real mechanism). An ``address is None`` issue yields the
            neutral peek placeholder, never a crash.

        Args:
            event (IssueRow.Selected): The row-activation message carrying the
                selected issue's integer address (or ``None``).

        Returns:
            None

        Dependencies:
            Uses:
                - ``_update_issues_hex_pane``
            Used by:
                - Textual message dispatch (from ``IssueRow``)
        """
        self._update_issues_hex_pane(event.address)

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
            # Derived loader facts belong to the NEW primary image — carry them
            # forward so the merge does not reset them to defaults (LLR-066.7).
            out_of_order_count=primary_loaded.out_of_order_count,
            entry_point=primary_loaded.entry_point,
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
            # The primary's derived loader facts survive the MAC overlay — carry
            # them forward so the merge does not reset them (LLR-066.7, AT-066d).
            out_of_order_count=existing.out_of_order_count,
            entry_point=existing.entry_point,
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

    def _mac_view_cache_key_for(
        self,
        records: list[dict],
        loaded: LoadedFile,
        a2l_data: Optional[dict],
    ) -> tuple:
        """
        Summary:
            Build the MAC-view cache key shared by the load worker
            (``_prepare_load_payload``) and ``update_mac_view`` so both sides agree
            on cache hits, including no-MAC sessions (LLR-037.4).

        Args:
            records (list[dict]): Normalized MAC record list (may be empty).
            loaded (LoadedFile): File the key describes (``current_file`` at render time).
            a2l_data (Optional[dict]): A2L payload identity component.

        Returns:
            tuple: ``(records_identity, len(records), id(a2l_data), file_type,
            ranges_tuple, mem_map_len)``.

        Raises:
            None

        Data Flow:
            - With records present, the identity component stays ``id(records)``
              (pre-LLR-037.4 behavior, unchanged).
            - With records EMPTY, ``mac_records or []`` builds a fresh list per call,
              so ``id(records)`` would churn and force a full payload recompute
              (including an S19 re-parse for the overlap set) on every render. The
              stable substitute chosen at Phase 3 is ``id(loaded)``: the ``LoadedFile``
              identity is shared by the worker (``loaded``) and the renderer
              (``self.current_file``), so worker-precomputed no-MAC reports register
              as cache HITS and repeat renders never recompute.

        Dependencies:
            Uses:
                - none
            Used by:
                - ``_prepare_load_payload``
                - ``update_mac_view``
                - ``_refresh_no_mac_validation``
        """
        records_identity = id(records) if records else id(loaded)
        return (
            records_identity,
            len(records),
            id(a2l_data),
            loaded.file_type,
            tuple(loaded.ranges),
            len(loaded.mem_map),
        )

    def _refresh_no_mac_validation(self) -> None:
        """
        Summary:
            Keep (or compute) the primary+A2L validation report when
            ``update_mac_view`` takes a no-MAC branch, instead of wiping
            ``_validation_report`` / ``_validation_issues`` (LLR-037.4, the B-1a
            fix). Sessions with NO primary file keep the historical clear.

        Args:
            None (reads ``current_file`` / ``current_a2l_data``; writes the four
            validation members on the clear path.)

        Returns:
            None

        Raises:
            None

        Data Flow:
            - No primary file: clear ``_validation_report`` / ``_validation_issues``
              and the issue cell caches (unchanged pre-fix behavior).
            - Primary present: build the empty-records cache key via
              ``_mac_view_cache_key_for`` (stable ``id(current_file)`` substitute) and,
              only on a key change, run ``_build_mac_view_cache`` — which routes
              through ``_compute_mac_view_payload`` / ``build_validation_report`` for
              the primary+A2L pair. On a key match (worker precompute or a repeat
              render) every validation member is retained untouched — never
              wipe-then-recompute.

        Dependencies:
            Uses:
                - ``_mac_view_cache_key_for``
                - ``_build_mac_view_cache``
            Used by:
                - ``update_mac_view`` (both no-MAC branches)
        """
        if not self.current_file:
            self._validation_report = None
            self._validation_issues = []
            return
        cache_key = self._mac_view_cache_key_for(
            [], self.current_file, self.current_a2l_data
        )
        if self._mac_view_cache_key != cache_key:
            self._mac_view_cache_key = cache_key
            self._build_mac_view_cache()

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
            - Bump ``_image_generation`` and push it into ``_change_service`` so a
              completed check run cannot keep describing the previous image
              (LLR-077.2).
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
        # batch-48 (LLR-077.2, the BL-4 arm): a NEW image is now installed, so
        # any completed check run describes a PREVIOUS one. Bump the monotonic
        # generation and push it into the change service, which compares it
        # against the token it stamped at run time and degrades every entry
        # glyph to `·` on a mismatch. The bump lives HERE — the single install
        # point F-09 below names — rather than in `_apply_loaded_file`: that
        # method is only the SYNCHRONOUS wrapper, and the worker path reaches
        # this method directly via `call_from_thread` (`_start_load_worker`),
        # so a bump one frame up would miss every real async load.
        #
        # This bumps on EVERY install, including a MAC/A2L attach that leaves
        # the image bytes alone — deliberately, and it is the conservative
        # direction, not an oversight. Over-refusing costs the analyst a
        # re-run and shows `·`, which is honest; under-refusing renders a
        # verdict that is a lie. Narrowing the trigger would mean deciding
        # here whether an install "really" changed the image, which is the
        # kind of inference that produced the BL-4 defect in the first place.
        self._image_generation += 1
        self._change_service.set_image_generation(self._image_generation)
        # ...and RE-RENDER the entries table, or the invalidation is invisible.
        # Nothing else re-renders it on load: the four existing `refresh_entries`
        # sites all hang off a Patch-Editor action, an undo/redo, or the panel's
        # own mount. So the stamp alone would go stale in the service while the
        # TABLE kept painting the verdicts of the previous image — the user-facing
        # half of the same defect. This is a render call over data the service
        # already holds; it re-derives nothing and applies nothing. (It also
        # refreshes each row's containment `status_text`, which was likewise
        # stale-until-next-action before this batch.)
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            # App not mounted (headless unit tests drive this pipeline on a
            # bare `S19TuiApp()` with no screen stack) — no tree to render
            # into, the same tolerance `_apply_empty_state` documents just
            # below. NOT a real-app path: the panel mounts during compose,
            # which precedes both `App.on_mount`'s startup load and any
            # user-triggered one. The service-side stamp above is set either
            # way, so nothing is skipped that a later render would need.
            pass
        else:
            panel.refresh_entries(self._change_service.rows(loaded.ranges))
        # F-09 (LLR-056.3): every load path — project load, loose-file
        # load, variant activation — funnels through this install point,
        # so the sticky report-filter selection dies with the previous
        # loaded-file set here (the batch-24 cross-project survivor
        # class). The project-CREATE swap, which installs no file, resets
        # in ``_handle_save_dialog``.
        self._report_filter_path = None
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
        mac_cache_key = self._mac_view_cache_key_for(records, loaded, a2l_data)
        mac_widths, mac_cell_rows, mac_cell_styles = precompute_mac_datatable_payload(
            mac_payload["rows"], mac_payload["meta"]
        )
        self.logger.info(
            "Load phase boundary: prepare_datatable_done mac_rows=%d widths=%s",
            len(mac_cell_rows),
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
            - Clear widget, refresh the Workspace stat pane and the whole-image
              memory strip, and short-circuit when no file is loaded.
            - Append at most ``MAX_SECTIONS_PRIMARY_RANGES`` memory-range rows,
              each an in-range ``✓`` glyph + cyan address, a humanized size
              (``human_bytes``) with the range's dominant entropy-band glyph, and
              a size micro-bar (``microbar(size / biggest, floor=True)``) as the
              third line (LLR-042.7 / batch-47 LLR-066.2), then a truncation row
              when more exist. The bar is floored to >=1 filled cell because at
              ``SECTIONS_COVERAGE_BAR_WIDTH`` (8) any range under 6.25% of the
              largest would otherwise render invisible (a 64 B vector table
              beside a 512 KiB image). OK/ERROR ``sev-*`` colouring is retained
              on the row label.
            - Append at most ``MAX_SECTIONS_OUT_OF_RANGE`` MAC out-of-range rows; when
              truncated, add a single summary row pointing users at the Issues panel.

        Dependencies:
            Uses:
                - ``_collect_mac_out_of_range_addresses``
                - ``css_class_for_severity``
                - ``dominant_band_label`` / ``band_style`` / ``human_bytes`` /
                  ``microbar``
                - ``update_workspace_stats``
                - ``update_memory_strip``
            Used by:
                - ``_apply_prepared_load``
        """
        sections = self.query_one("#sections_list", ListView)
        sections.clear()
        self.update_workspace_stats()
        self.update_memory_strip()
        if not self.current_file:
            return
        ranges = self.current_file.ranges
        validity = self.current_file.range_validity
        total_ranges = len(ranges)
        range_cap = MAX_SECTIONS_PRIMARY_RANGES
        visible_ranges = list(zip(ranges[:range_cap], validity[:range_cap]))
        max_size = max((end - start for (start, end), _ in visible_ranges), default=0)
        entropy_windows = self.current_file.entropy_windows
        for (start, end), is_valid in visible_ranges:
            size = end - start
            band_glyph = ""
            if entropy_windows:
                band_label = dominant_band_label(entropy_windows, start, end)
                if band_label is not None:
                    band_glyph = band_style(band_label)[1]
            content = Text()
            content.append("✓ ", style=GREEN)
            content.append(f"0x{start:08X}\n", style=CYAN)
            content.append(f"– 0x{end - 1:08X}  ")
            content.append(human_bytes(size).rjust(9), style=VALUE)
            if band_glyph:
                content.append(f" {band_glyph}")
            content.append("\n")
            content.append_text(
                microbar(
                    size / max_size if max_size else 0.0,
                    SECTIONS_COVERAGE_BAR_WIDTH,
                    floor=True,
                )
            )
            label = Label(content)
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
            label = Label(f"MAC out-of-range\n@ 0x{address:08X}")
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

    def update_workspace_stats(self) -> None:
        """
        Summary:
            Refresh the Workspace stat pane (``#ws_right`` → ``#ws_stats``) with
            coverage percent + range count and error / warning tallies
            (LLR-042.9 / US-040c). Display arithmetic only — it reuses
            ``coverage_stats`` and counts ``_validation_issues`` by severity;
            it performs no new parse / coverage / validation. No entropy figure
            (D3 descoped).

        Args:
            None

        Returns:
            None

        Data Flow:
            - With no file loaded, render the neutral empty pane (0 ranges,
              coverage ``—``).
            - Otherwise compute ``coverage_stats`` over the already-parsed
              ``ranges`` / ``range_validity`` and the pre-computed
              ``_validation_issues``, tally ERROR / WARNING counts, and render
              the markup-safe stat text into ``#ws_stats``, followed by the
              loader-facts line (``Loader N err · ⚠K OOO · Entry <hex-or-—>``,
              batch-47 LLR-066.4) built from the derived ``LoadedFile`` fields.

        Dependencies:
            Uses:
                - ``coverage_stats``
                - ``build_workspace_stats_text``
                - ``build_loader_facts_text``
            Used by:
                - ``update_sections``
        """
        # Render-defensive: ``update_sections`` also runs in unit tests that drive
        # a non-mounted app with a fake ``query_one`` (returns None for widgets they
        # don't stub) and pre-mount, where ``#ws_stats`` is absent. Either case is a
        # no-op, not a crash (mirrors ``update_memory_strip``).
        try:
            body = self.query_one("#ws_stats", Static)
        except Exception:  # noqa: BLE001 — display-side, non-fatal
            return
        if body is None:
            return
        if not self.current_file:
            body.update(build_workspace_stats_text(coverage_stats([], [], []), 0, 0))
            return
        stats = coverage_stats(
            self.current_file.ranges,
            self.current_file.range_validity,
            self._validation_issues,
        )
        error_count = sum(
            1 for issue in self._validation_issues
            if issue.severity is ValidationSeverity.ERROR
        )
        warning_count = sum(
            1 for issue in self._validation_issues
            if issue.severity is ValidationSeverity.WARNING
        )
        text = build_workspace_stats_text(stats, error_count, warning_count)
        text.append("\n")
        text.append_text(
            build_loader_facts_text(
                len(self.current_file.errors),
                self.current_file.out_of_order_count,
                self.current_file.entry_point,
            )
        )
        body.update(text)

    def update_memory_strip(self) -> None:
        """
        Summary:
            Refresh the Workspace whole-image memory strip (``#ws_memstrip``): a
            single-row band whose mapped cells are coloured by their dominant
            entropy band (``entropy_style.band_style`` over the loader-computed
            ``current_file.entropy_windows``) and whose unmapped gaps get the
            ``╱`` hatch (batch-47, LLR-067.1/067.2). When no entropy windows are
            present it FALLS BACK to the batch-27 valid / invalid / gap colouring
            via ``cell_status`` / ``status_to_css_class`` (LLR-067.3). The
            mounted cell count is BOUNDED to the band's measured content width
            via ``cell_count_for_geometry`` (rows=1), so a hostile huge image
            never mounts unbounded cells. Display arithmetic only — no new parse
            / coverage / validation / entropy computation.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Clear the band; with no file loaded or no positive image span,
              leave a neutral empty band (no cells, no crash).
            - Otherwise build the ``(start, end, is_valid)`` triples from the
              parsed model, derive the image span, cap the cell count to the
              measured band width (fallback ``WORKSPACE_MEMSTRIP_DEFAULT_COLS``),
              and mount one ``Static`` cell per window coloured by ``cell_status``
              → ``status_to_css_class``.

        Dependencies:
            Uses:
                - ``derive_image_span`` / ``cell_count_for_geometry`` /
                  ``bytes_per_cell`` / ``cell_status`` / ``status_to_css_class``
                  / ``dominant_band_label`` / ``band_style`` / ``safe_text``
            Used by:
                - ``update_sections``
        """
        try:
            band = self.query_one("#ws_memstrip", Container)
        except Exception:  # noqa: BLE001 — display-side, non-fatal
            # App not mounted yet (headless render before compose).
            return
        if band is None:
            # Unit tests drive ``update_sections`` with a fake ``query_one`` that
            # returns None for widgets they don't stub — no-op, not a crash.
            return
        band.remove_children()
        if not self.current_file:
            return
        ranges = self.current_file.ranges
        validity = self.current_file.range_validity
        span_start, span_end = derive_image_span(ranges)
        span = span_end - span_start
        if not ranges or span <= 0:
            return
        ordered: list[tuple[int, int, bool]] = []
        for index, (start, end) in enumerate(ranges):
            is_valid = bool(validity[index]) if index < len(validity) else True
            ordered.append((start, end, is_valid))
        ordered.sort(key=lambda item: item[0])
        size = band.content_size
        cols = size.width if size.width > 0 else WORKSPACE_MEMSTRIP_DEFAULT_COLS
        count = cell_count_for_geometry(span, cols, 1)
        per_cell = bytes_per_cell(span, count)
        entropy_windows = self.current_file.entropy_windows
        cells: list[Static] = []
        for index in range(count):
            cell_start = span_start + index * per_cell
            cell_end = min(span_end, cell_start + per_cell)
            status = cell_status(cell_start, cell_end, ordered)
            if entropy_windows:
                # Entropy-banded view (batch-47, LLR-067.1/067.2): gaps get the
                # app-supplied ``╱`` hatch; mapped cells take their dominant
                # band's glyph + ``band-*`` class from ``entropy_style``.
                if status == "gap":
                    cells.append(
                        Static(
                            safe_text(_STRIP_GAP_GLYPH),
                            classes=f"strip-cell {status_to_css_class('gap')}",
                        )
                    )
                    continue
                band_label = dominant_band_label(entropy_windows, cell_start, cell_end)
                if band_label is not None:
                    band_class, glyph, _meaning = band_style(band_label)
                    cells.append(
                        Static(
                            safe_text(glyph),
                            classes=f"strip-cell {band_class}",
                        )
                    )
                    continue
            # No entropy windows (LLR-067.3 fallback) or a mapped cell with no
            # overlapping window: keep the pre-existing valid/invalid/gap band.
            sev_class = status_to_css_class(status)
            cells.append(
                Static(
                    safe_text(_STRIP_CELL_GLYPH),
                    classes=f"strip-cell {sev_class}",
                )
            )
        if cells:
            band.mount(*cells)

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
            - Otherwise pass ``current_file.ranges``,
              ``current_file.range_validity``, the pre-computed
              ``_validation_issues``, the enriched ``_a2l_enriched_tags``
              (R-TUI-041 R-3 region/cell symbol naming) and the loader-computed
              ``current_file.entropy_windows`` (batch-45 R-TUI-060 band view)
              straight through to ``MemoryMapPanel.render_ranges``. The renderer
              reads these already-computed model fields verbatim — it adds no
              coverage computation, entropy computation, parsing or analysis
              (LLR-012.1 / LLR-012.4 / LLR-045A.2 M4).

        Dependencies:
            Uses:
                - ``MemoryMapPanel.render_ranges``
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
        """
        panel = self.query_one("#memory_map_panel", MemoryMapPanel)
        if not self.current_file:
            panel.render_ranges([], [], [], [], [])
            return
        panel.render_ranges(
            self.current_file.ranges,
            self.current_file.range_validity,
            self._validation_issues,
            self._a2l_enriched_tags,
            self.current_file.entropy_windows,
            self.current_file.mem_map,
        )
        self.logger.info(
            "Memory Map updated. ranges=%d", len(self.current_file.ranges)
        )

    def on_memory_map_panel_open_in_hex_requested(
        self, message: "MemoryMapPanel.OpenInHexRequested"
    ) -> None:
        """Jump to the hex view focused on the selected cell (LLR-041.6).

        Summary:
            Handle the Memory Map's Open-in-Hex request by switching to the
            Workspace/hex screen and driving the existing
            ``update_hex_view(focus_address=…)`` with the cell's start address.
            The panel renders no hex itself — this app-side handler is the
            single owner of the focus path.

        Args:
            message (MemoryMapPanel.OpenInHexRequested): Carries the selected
                cell's ``focus_address`` (its ``cell_start``).

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_show_screen`` / ``update_hex_view``
            Used by:
                - Textual message dispatch (from ``MemoryMapPanel``)
        """
        message.stop()
        self.action_show_screen("workspace")
        self.update_hex_view(focus_address=message.focus_address)

    def _snapped_focus_row_index(
        self, focus_address: int, row_bases: list[int]
    ) -> Optional[int]:
        """
        Summary:
            Resolve a focus address to the index of the nearest present
            16-aligned row base — exact when present, else the first row
            at-or-after the focus, else the last row before it (batch-31
            AC-1 / B-01).

        Args:
            focus_address (int): The requested focus address (need not be
                present in the image — e.g. a coarse Memory-Map cell start).
            row_bases (list[int]): The image's ascending present row bases.

        Returns:
            Optional[int]: Index into ``row_bases``, or ``None`` when the
            list is empty.

        Data Flow:
            - Align the focus down to its 16-byte row, then bisect the
              sorted ``row_bases`` for the exact/at-or-after/before match.

        Dependencies:
            Uses:
                - ``bisect.bisect_left``
            Used by:
                - ``update_hex_view`` (window reposition on focus)
        """
        if not row_bases:
            return None
        from bisect import bisect_left

        focus_base = focus_address - (focus_address % 16)
        index = bisect_left(row_bases, focus_base)
        if index < len(row_bases):
            return index
        return len(row_bases) - 1

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
                # batch-31 AC-1 (B-01): snap to the nearest present row
                # instead of requiring exact row-base membership — a coarse
                # Memory-Map cell start rarely coincides with a present row,
                # and the old exact guard silently left the window in place.
                focus_index = self._snapped_focus_row_index(focus_address, row_bases)
                if focus_index is not None:
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
            - Short-circuit when no MAC records are loaded (empty table + summary);
              a session WITH a primary file still computes/retains the primary+A2L
              validation report via ``_refresh_no_mac_validation`` (LLR-037.4) —
              only no-primary sessions clear the validation members.
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
                - ``_refresh_no_mac_validation`` / ``_mac_view_cache_key_for``
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
        # Blank the coverage strip by default; the loaded-MAC path re-shows it
        # below (LLR-071.2 — gated on a MAC being loaded, not on file type).
        self._update_mac_coverage_strip(show=False)
        if not self.current_file or not self.current_file.mac_records:
            summary_label.update("No MAC loaded.")
            self._refresh_no_mac_validation()
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
            self._refresh_no_mac_validation()
            self.update_validation_issues_view()
            self.logger.info(
                "Load phase boundary: populate_mac_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        cache_key = self._mac_view_cache_key_for(
            records, self.current_file, self.current_a2l_data
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
        self._update_mac_coverage_strip(show=True)
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

    def _update_mac_coverage_strip(self, *, show: bool) -> None:
        """
        Summary:
            Render (or blank) the always-visible MAC coverage strip
            ``#mac_coverage_strip`` (batch-47, LLR-071.1/071.2). When a MAC is
            loaded the strip shows ``build_mac_coverage_strip`` from the session's
            ``CoverageMetrics`` — independent of the primary file type,
            superseding the old primary-only pct-line. When no MAC is loaded the
            strip is blanked.

        Args:
            show (bool): True → render the coverage strip; False → blank it.

        Returns:
            None

        Data Flow:
            - Read ``self._validation_report.coverage`` (or ``None`` when no
              report exists yet) and hand it to ``build_mac_coverage_strip``,
              which formats a numeric-only, C-17-safe Rich ``Text``.
            - Defensively no-op when the strip node is not mounted (headless unit
              tests that fake ``query_one``).

        Dependencies:
            Uses:
                - ``build_mac_coverage_strip``
            Used by:
                - ``update_mac_view``
        """
        try:
            strip = self.query_one("#mac_coverage_strip", Static)
        except Exception:
            return
        if strip is None:
            return
        if not show:
            strip.update("")
            return
        report = self._validation_report
        coverage = report.coverage if report is not None else None
        strip.update(build_mac_coverage_strip(coverage))

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
            - Fold a leading status glyph (``✓``/``⚠``/``✗``, coloured per the
              precomputed ``Status`` column via ``_mac_status_glyph``) into the
              Tag cell as its own span, then append the file-derived name in the
              row severity style (batch-47, LLR-070.1/070.2 — the name is a
              ``Text`` segment, never markup-parsed).
            - Colour the Address cell cyan (LLR-070); style the rest by severity.
            - Build row-key strings of the form ``mac:<absolute_index>``.
            - Record the per-row address in ``_mac_row_key_to_address`` for jump logic.
            - Invoke ``DataTable.add_row`` once per row (per-row key).

        Dependencies:
            Uses:
                - ``_mac_status_glyph``
            Used by:
                - ``update_mac_view``
        """
        if not visible_rows:
            return
        rendered_rows: list[tuple] = []
        keys: list[str] = []
        for i, row in enumerate(visible_rows):
            style = visible_styles[i] if i < len(visible_styles) else ""
            status = str(row[4]) if len(row) > 4 else ""
            in_mem = str(row[3]) if len(row) > 3 else ""
            glyph, glyph_style = _mac_status_glyph(status, in_mem)
            rich_cells: list[Text] = []
            for col, cell in enumerate(row):
                cell_str = str(cell)
                if col == 0:
                    tag_cell = Text()
                    tag_cell.append(f"{glyph} ", style=glyph_style)
                    tag_cell.append(cell_str, style=style or None)
                    rich_cells.append(tag_cell)
                elif col == 1:
                    rich_cells.append(Text(cell_str, style=CYAN))
                else:
                    rich_cells.append(Text(cell_str, style=style) if style else Text(cell_str))
            rendered_rows.append(tuple(rich_cells))
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
        """
        Summary:
            Render buffered A2L summary and tag views, refreshing MAC/validation
            state BEFORE the tag rows render so their severity map is fresh.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Data Flow:
            - A2L absent: clear enrichment/filter/find state, render empty views,
              refresh the MAC view, and (with no primary file) clear the
              validation members.
            - A2L present: enrich tags first, then call ``update_mac_view()`` —
              AFTER enrichment because ``_build_mac_view_cache`` consumes
              ``self._a2l_enriched_tags``, and BEFORE ``_refresh_a2l_filtered_tags``
              so the issue list read by the row-severity map reflects the current
              file pair on the sync-fallback load path (LLR-037.3; the call is
              idempotent over ``_mac_view_cache_key``, so the reorder adds no
              recomputation).

        Dependencies:
            Uses:
                - ``_compute_a2l_enriched_tags`` / ``update_mac_view``
                - ``_refresh_a2l_filtered_tags`` / ``_update_a2l_summary_buffer``
                - ``update_a2l_tags_view`` / ``update_validation_issues_view``
            Used by:
                - ``_apply_prepared_load`` (``_step_a2l``)
                - A2L clear/reload handlers
        """
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
        # LLR-037.3: install the validation issue list after enrichment (the
        # MAC-view cache consumes _a2l_enriched_tags) and before the tag rows
        # render, so the first frame reads a fresh issue-severity map.
        self.update_mac_view()
        filter_input = self.query_one("#a2l_tags_filter_input", Input)
        self.a2l_tags_filter_text = filter_input.value.strip()
        self._refresh_a2l_filtered_tags(preserve_anchor=False)
        self._update_a2l_summary_buffer()

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
            - Build the issue-severity map from ``self._validation_issues`` once
              per render (LLR-037.2 map-build ownership) and pass it to
              ``_a2l_tag_row_severity`` so ERROR-issue symbols red their rows.
            - Build 16-cell tuples with the same fields the prior renderer produced,
              wrap each cell in a severity-styled ``rich.text.Text``, and insert
              via per-row ``add_row`` with ``a2l:<absolute_index>`` keys.

        Dependencies:
            Uses:
                - ``_a2l_clamp_page_start`` / ``_get_window_bounds``
                - ``_a2l_issue_severity_map``
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
        issue_severity_map = _a2l_issue_severity_map(self._validation_issues)
        for i, tag in enumerate(visible_tags):
            absolute_index = start + i
            row_key = f"a2l:{absolute_index}"
            self._a2l_row_key_to_tag[row_key] = tag
            cells = self._build_a2l_table_cells(tag)
            severity = _a2l_tag_row_severity(tag, issue_severity_map)
            style = _severity_style(severity)
            # LLR-068.1: the builder returns markup-safe Rich ``Text`` cells with
            # per-cell accents (name/address/source). Row-level severity (US-033,
            # the A2L Red/Green/White/Grey contract) overrides those accents when
            # present, preserving the pre-batch uniform per-row colouring.
            if style:
                for cell in cells:
                    cell.style = style
            try:
                a2l_table.add_row(*cells, key=row_key)
            except Exception:
                a2l_table.add_row(*cells)
        page_num = start // page_size + 1
        total_pages = max(1, (total_tags + page_size - 1) // page_size)
        in_image = sum(1 for tag in tags if tag.get("in_memory"))
        summary_text = Text(
            f"Page {page_num}/{total_pages} | tags {start + 1}-{end} / {total_tags} "
            f"(page size {page_size}; +/- to change page)"
        )
        summary_text.append("  ·  ")
        summary_text.append(f"{in_image} in image", style=GREEN)
        summary_label.update(summary_text)
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

    def _build_a2l_table_cells(self, tag: dict) -> tuple[Text, ...]:
        """
        Summary:
            Project one enriched A2L tag into the 16-cell tuple the DataTable row
            expects, keeping every field the previous ListView renderer surfaced
            (batch-47, LLR-068.1/068.3). Every cell is a markup-safe Rich
            ``Text`` (built via ``safe_text``), so every file-derived value —
            name, source, unit, function group, memory region, raw/physical
            value — renders literally and can never be interpreted as Rich
            markup (C-17). The name cell carries a leading in-image glyph
            (``✓`` when ``tag["in_memory"]`` is truthy, else ``·``); the name is
            bright, the address cyan, the source muted. Row-level severity
            colouring is layered on top by ``update_a2l_tags_view`` (it overrides
            these accent styles when a severity applies), preserving the A2L
            Red/Green/White/Grey row-colour contract.

        Args:
            tag (dict): Enriched A2L tag with value, memory, and schema fields.

        Returns:
            tuple[Text, ...]: 16-cell tuple of Rich ``Text`` aligned with the
            DataTable columns; the name cell (index 0) carries the leading
            in-image glyph.

        Data Flow:
            - Format address/length/limits defensively so missing fields stay blank.
            - Reuse ``_a2l_tag_in_memory_display`` / ``_a2l_tag_unit_display`` helpers
              so display conventions remain centralized.
            - Wrap each cell via ``safe_text`` (``Text`` constructor, never
              ``Text.from_markup``) so the tuple is markup-safe by construction.

        Dependencies:
            Uses:
                - ``_a2l_tag_in_memory_display``
                - ``_a2l_tag_unit_display``
                - ``safe_text`` ; ``VALUE`` / ``CYAN`` / ``DGRAY``
            Used by:
                - ``update_a2l_tags_view``
        """
        addr = tag.get("address")
        length = tag.get("length")
        addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
        len_text = str(length) if isinstance(length, int) else "n/a"
        name_text = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
        glyph = "✓" if tag.get("in_memory") else "·"
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
            safe_text(f"{glyph} {name_text}", style=VALUE),
            safe_text(addr_text, style=CYAN),
            safe_text(len_text),
            safe_text(source_text, style=DGRAY),
            safe_text(raw_value_text),
            safe_text(physical_value_text),
            safe_text(in_mem_text),
            safe_text(region_text),
            safe_text(limits_text),
            safe_text(unit_text),
            safe_text(bit_text),
            safe_text(endian_text),
            safe_text(virt_text),
            safe_text(func_text),
            safe_text(access_text),
            safe_text(dtype_text),
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
        for field_name in self.a2l_tags_filter_fields:
            label = f"(*) {field_name}" if field_name == self.a2l_tags_filter_field else f"( ) {field_name}"
            item = ListItem(Label(label))
            item.data = field_name
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
            - Chains ``_refresh_patch_variant_select`` (US-028 / LLR-035.3):
              every variant-set mutation site (project load/save, variant
              append, activation apply) already funnels through this
              refresh, so the Patch Editor's variant dropdown re-syncs on
              the same trigger set with no extra call sites.

        Dependencies:
            Uses:
                - ``CommandBar.set_context_labels``
                - ``_variant_display_options``
                - ``_refresh_patch_variant_select``
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
        self._refresh_patch_variant_select()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # The Direction B restyle retires the `#view_bar` button bar
        # (view_hex/a2l/mac_button, settings_button) — rail items 1-3
        # supersede the view-toggle buttons (LLR-004.4 / A-07).
        if event.button.id == "search_button":
            self._handle_search()
        elif event.button.id == "ws_load_project_button":
            # batch-31 AC-7 (B-20): visible Workspace entry point to the
            # existing key-`p` load-project flow.
            self.action_load_project()
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
        elif event.button.id in (
            "mac_legend_button",
            "issues_legend_button",
        ):
            self.action_show_legend()

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
