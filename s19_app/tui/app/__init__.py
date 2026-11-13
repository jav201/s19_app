"""s19_app.tui.app — re-exports (moved from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field, replace
import copy
import hashlib
import json
import logging
import os
import re
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import shutil
import stat
import time
from datetime import datetime, timezone
from typing import Any, Callable, List, Literal, Mapping, Optional, Sequence, Tuple
from textual import events, work
from textual.actions import SkipAction
from textual.app import App, ComposeResult
from textual.geometry import Offset
from textual.message import Message
from textual.binding import Binding
from textual.screen import Screen
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.timer import Timer
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    Button,
    DataTable,
    Header,
    HelpPanel,
    Input,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    Select,
    Static,
    TextArea,
)
from rich.cells import cell_len, set_cell_size
from rich.text import Text
from ...compare import DIFF_KIND_DOMAIN
from ...core import S19File, S19_INTEGRITY_NOTICE_CODES, load_notice_code
from ...hexfile import HEX_INTEGRITY_NOTICE_CODES, IntelHexFile
from ..a2l_parse import parse_a2l_file
from ..changes import STATUS_VERIFIED, VerifyResult
from ..changes.verify import verify_written_image
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ...render.hexview import (
    build_row_bases,
    find_string_in_mem,
    hex_row_bases,
    render_hex_view_text,
)
from ...utils import safe_text
from ..changes.apply import render_patched_image, save_patched_image
from ..changes.check import run_check_document
from ..changes.io import (
    CHG_ENCODING_UNKNOWN,
    CHG_FORMAT,
    CHG_KIND_UNKNOWN,
    CHG_V1_FORMAT,
    CHG_VALUE_MODE_UNKNOWN,
    DUMMY_CHANGESET_TEXT,
    MF_BAD_STRUCTURE,
    MF_JSON_PARSE,
    SYMBOL_NO_A2L_CONTEXT_TEXT,
    list_change_documents,
    parse_change_document,
    read_change_document,
    serialize_change_document,
    write_change_document,
)
from ..changes.model import (
    DISPOSITION_APPLIED,
    DISPOSITION_BLOCKED,
    ChangeDocument,
    ChangeEntry,
    ChangeSummary,
)
from ..command_bar import CommandBar, PaletteEntry
from ..mac import parse_mac_file
from ..models import LoadedFile, ProjectVariantSet, VariantDescriptor
from ..operations import get_operation, list_operation_ids
from ..os_clipboard_input import OsClipboardInput, _mirror_and_write_os_clipboard
from ..capped_text_area import CappedTextArea
from ..rail import Rail, RailEntry, RailItem, RAIL_ENTRIES
from ..screens import (
    ChangeSetJsonScreen,
    ConfirmDiscardScreen,
    ConfirmQuestionScreen,
    EntryJsonScreen,
    FileRefCandidate,
    FileRefChoice,
    FileRefChooserScreen,
    FlowBlockEditScreen,
    LegendScreen,
    LOAD_RESULT_SELECT_VARIANT,
    LoadChoice,
    LoadDialog,
    LoadFlowScreen,
    LoadResultScreen,
    OperationsScreen,
    ReportViewerScreen,
    SaveFlowScreen,
    SavePreview,
    SaveProjectPayload,
    SaveProjectScreen,
    SelectVariantScreen,
)
from ..flow_screens import (
    BrowseRequested,
    FlowBuilderPanel,
    FlowExecutionPanel,
    FlowRefContext,
    fx_run_error_line,
)
from ..screens_directionb import (
    AbDiffPanel,
    CheckEditorPanel,
    CoverageStats,
    EmptyStatePanel,
    LoadedArtifactsPanel,
    LoadGuardScreen,
    MemoryMapPanel,
    PatchDocumentView,
    PatchEditorPanel,
    bytes_per_cell,
    cell_count_for_geometry,
    cell_status,
    coverage_stats,
    derive_image_span,
    status_to_css_class,
)
from ..crc_designer_view import CrcDesignerPanel
from ..color_policy import css_class_for_severity
from ..entropy_style import band_style
from ..insight_style import CYAN, DGRAY, GREEN, LABEL, RED, VALUE, YELLOW, human_bytes, microbar
from ..services.entropy_service import EntropyWindow
from ..issues_view import (
    _GROUP_DISPLAY_MAX,
    GroupedIssuesPanel,
    IssueRow,
    SEVERITY_ORDER,
    build_issues_severity_strip,
)
from ..checks_view import (
    CHECK_GROUP_ORDER,
    CheckRow,
    GroupedChecksPanel,
    build_checks_aggregate_strip,
)
from ...validation import ValidationIssue, ValidationReport, ValidationSeverity
from ..services.a2l_service import enrich_tags_and_render
from ..services.before_after_service import compose_before_after_report
from ..services.change_service import ChangeActionResult, ChangeService, save_back_status_suffix
from ..services.compare_service import (
    SOURCE_EXTERNAL,
    SOURCE_PROJECT_VARIANT,
    ImageSource,
    compare_images,
)
from ..services.diff_report_service import (
    flow_change_attribution,
    generate_diff_report,
    generate_diff_report_html,
)
from ..services.load_service import build_loaded_hex, build_loaded_s19
from ..services.report_addendum import DeclaredRegion
from ..services.report_filter import (
    ReportFilterMatcher,
    parse_report_filter,
    read_report_filter_text,
    resolve_report_filter,
)
from ..services.report_service import (
    EXECUTION_SCOPE_TO_REPORT_MODE,
    REPORT_SOURCE_DEFAULT,
    REPORT_SOURCE_MANIFEST,
    ReportOptions,
    generate_project_report,
    list_project_reports,
)
from ..services.manifest_writer import (
    ManifestVerifyResult,
    MANIFEST_VERIFIED,
    check_project_files,
    derive_record,
    project_file_records,
    serialize_manifest,
    verify_written_manifest,
    write_project_manifest,
)
from ..services.project_gather_service import (
    GATHER_DOCUMENT_NOT_RECORDED,
    PLAN_ACTION_KEEP,
    PLAN_ACTION_NEW,
    PLAN_ROLE_CARRIED,
    PLAN_ROLE_DOCUMENT,
    PLAN_ROLE_MANIFEST,
    PLAN_TARGET_MERGE,
    PLAN_TARGET_NEW,
    PLAN_TARGET_OPEN,
    PROJECT_CHECKS_DIR,
    PROJECT_HOME_NAMES,
    PROJECT_PATCHES_DIR,
    InventoryFile,
    PlannedFile,
    ProjectInventory,
    SavePlan,
    SavePlanRow,
    classify_active_document,
    document_home_for_kind,
    gather_project_artifacts,
    inventory_project_tree,
    PAINTED_NAME_LIMIT,
    painted_names,
    plan_project_save,
    scoped_home,
    scoped_home_target,
)
from ..services import folder_open_service
from .. import workspace
from ..open_folder_chip import OpenFolderChip, titled_header
from ..window_help import KeyBar, WindowHelpChip, WindowSection
from ..a2l_describe import CurveDescriptionScreen
from ..a2l import A2LProgress, describe_curve_tag
from ..segment_split_view import SplitJoinWindow
from ..services.validation_service import build_mac_coverage_strip, build_validation_report
from ..services.variant_execution_service import (
    DOCUMENT_NEXT_STEP,
    DOCUMENT_REASON_IO_ERROR,
    DOCUMENT_REASON_LINK,
    DOCUMENT_REASON_TOO_LARGE,
    DOCUMENT_REASON_UNREADABLE,
    EXECUTION_SCOPES,
    PROBLEM_NOT_READABLE,
    PROJECT_MANIFEST_NAME,
    SCOPE_ACTIVE,
    STEP_CHECK_THEN_LOAD,
    STEP_OPEN_FROM_EDITOR,
    STEP_REPLACE_A2L,
    _ISSUE_ENTRY,
    _ISSUE_KEY,
    _KEY_ACTIVE_DOCUMENT,
    DerivedFrom,
    FileRecord,
    LoadAnnouncement,
    ProjectFileProblem,
    ProjectManifest,
    VariantExecutionResult,
    compose_load_announcement,
    document_problem_file,
    execute_project_variants,
    is_active_document_form,
    manifest_is_damaged,
    manifest_keep_reason,
    manifest_rewrite_refusal,
    read_project_manifest,
)
from ..workspace import (
    _guarded_destination,
    _is_reparse_point,
    _path_traverses_reparse_point,
    _private_stage_dir,
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    PROJECT_NAME_MAX_CHARS,
    PlacementResult,
    RESERVED_WORKAREA_HOMES,
    S19_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_DIRNAME,
    WORKAREA_PATCHES,
    WORKAREA_TEMP,
    WORKAREA_TEMPLATES,
    WorkareaContainmentError,
    WorkareaPlacementError,
    build_variant_set,
    contained_in_workarea,
    copy_into_workarea,
    ensure_workarea,
    is_windows_device_name,
    list_workarea_files,
    place_into_workarea,
    RECENT_PROBLEM_TOO_LARGE,
    RECENT_PROBLEM_UNREADABLE,
    record_recent_source,
    read_recent_sources,
    recent_kind,
    resolve_input_path,
    sanitize_project_name,
    setup_logging,
    validate_project_files,
)
from .deps import (
    parse_a2l_cached,
    _SAVE_FULL_PATH_LIMIT,
    _image_map,
    _file_digest,
    _plan_without_document_key,
    _is_link_stat,
    recorded_document_state,
)
from .shared import (
    _TYPED_REFUSAL_TOKENS,
    BusyKey,
    _BusyAction,
    _BusyRun,
    _SAVEBACK_S0_MAX_BYTES,
    _A2L_ISSUE_SEVERITY_RANK,
    A2LCacheEntry,
    _LOG,
    PreparedLoad,
    _MAC_COLUMN_HEADERS,
    _SEVERITY_TO_RICH_STYLE,
    _severity_style,
    _MAC_GLYPH_PARSE_ERROR,
    _MAC_GLYPH_OUT_OF_IMAGE,
    _MAC_GLYPH_IN_IMAGE,
    _MAC_GLYPH_UNCHECKED,
    _A2L_CARD_HINT,
    _card_value_text,
    _card_field,
    _a2l_detail_card_text,
    _CopyRowTable,
    A2LTagTable,
    A2LDetailCard,
    _INTEGRITY_NOTICE_CODES,
    precompute_mac_datatable_payload,
    _has_primary,
    _has_mac,
    _has_a2l,
    _ProjectImageStep,
    _SaveSession,
    _PreparedSave,
    REOPEN_MAX_BYTES,
    REOPEN_MAX_ENTRIES,
    DOCUMENT_OK,
    DOCUMENT_MISSING,
    DOCUMENT_LINK,
    DOCUMENT_TOO_LARGE,
    DOCUMENT_UNREADABLE,
    DOCUMENT_IO_ERROR,
    _DOCUMENT_IN_HOME,
    _DOCUMENT_FILE_FAULT_CODES,
    _DOCUMENT_PARSE_ERRORS,
    RecordedDocumentState,
)
from .shared_io import (_plan_row_mismatch)
from .core import (
    _LOAD_DIALOG_INERT_ACTIONS,
    _BusyState,
    _QUIT_TITLE,
    _QUIT_BODY,
    _QUIT_YES,
    _QUIT_NO,
    _COPY_QUIT_BODY,
    _QuitQuestionScreen,
    _CopyQuitScreen,
    _RightGesture,
    RAIL_ENTRIES_B94,
    S19TuiApp,
    main,
)
from .save_commit import (
    SaveImageInput,
    SaveRequest,
    SaveOutcome,
    _save_failure_outcome,
    _SAVE_SUMMARY_CHANGED,
    _PlacedFiles,
    _save_clears_panel_flag,
)
from .reports import (REPORT_FILTERS_DIR_NAME, format_report_log_line)
from .patch import (PATCH_ACTIONS_V2, _synth_s0_header_from_filename)
from .checks_diff import (CHECK_EDITOR_ACTIONS)
from .save_plan import (
    _SAVE_REPORT_SUFFIX_CHARS,
    _save_manifest_keys,
    _SAVE_KIND_WORDS,
    _SAVE_ROW_LABELS,
    _SAVE_REFUSAL_PREFIX,
    _UNSET,
    _DOCUMENT_UNREADABLE_KEY,
    _unreadable_text,
    _PLACED_DOCUMENT_CLASSES,
    _DOCUMENT_DROP_OUTCOMES,
    _DOCUMENT_DROP_REASON,
)
from .project_load import (
    _RECENT_PROBLEM_STEPS,
    QuestionKind,
    UnsavedItem,
    ProjectLoadRequest,
    PreparedProjectLoad,
    InstallSet,
    choose_install_set,
    _DOCUMENT_REASON,
    _DOCUMENT_STEP,
    _SESSION_SNAPSHOT_NAMES,
)
from .file_load import (A2LAttachRequest, A2LAttachResult)
from .loaded_state import (_integrity_notice_codes, _unload_a2l, _unload_mac, _unload_primary)
from .workspace_view import (
    MAX_SECTIONS_OUT_OF_RANGE,
    MAX_SECTIONS_PRIMARY_RANGES,
    SECTIONS_COVERAGE_BAR_WIDTH,
    WORKSPACE_MEMSTRIP_DEFAULT_COLS,
    _STRIP_CELL_GLYPH,
    _STRIP_GAP_GLYPH,
    dominant_band_label,
    build_loader_facts_text,
    build_workspace_stats_text,
)
from .a2l_view import (
    _a2l_tag_in_memory_display,
    _a2l_tag_unit_display,
    _a2l_issue_severity_map,
    _a2l_tag_row_severity,
    _shorten_tag_name,
)
from .mac_view import (_build_a2l_name_index, _mac_record_ui_state, _mac_status_glyph)
from .issues_checks import (_ISSUE_DISPLAY_RANK)
from .shell import (
    _BUSY_FRAMES,
    _BUSY_TICK_SECONDS,
    _BUSY_ACTIONS,
    SESSION_ACTION_KEYS,
    _BUSY_LINE,
    _MAC_COPY_GLYPHS,
)
