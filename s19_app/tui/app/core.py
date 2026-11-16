"""s19_app.tui.app.core — S19TuiApp core (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, List, Optional, Tuple
from textual import events
from textual.actions import SkipAction
from textual.app import App, ComposeResult
from textual.geometry import Offset
from textual.binding import Binding
from textual.screen import Screen
from textual.containers import Container, Horizontal
from textual.timer import Timer
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button, Header, HelpPanel, Input, ListView, ProgressBar
from ..changes.model import ChangeDocument
from ..command_bar import CommandBar
from ..models import LoadedFile, ProjectVariantSet
from ..rail import Rail, RailEntry, RAIL_ENTRIES
from ..screens import ConfirmQuestionScreen, LoadDialog, SavePreview, SaveProjectScreen
from ..flow_screens import FlowExecutionPanel, fx_run_error_line
from ..screens_directionb import PatchEditorPanel
from ...validation import ValidationIssue, ValidationReport
from ..services.change_service import ChangeService
from ..services.report_addendum import DeclaredRegion
from ..services.manifest_writer import ManifestVerifyResult
from ..window_help import KeyBar
from ..segment_split_view import SplitJoinWindow
from ..services.variant_execution_service import LoadAnnouncement, VariantExecutionResult
from ..workspace import ensure_workarea, setup_logging
from . import deps
from .shared import (BusyKey, _BusyRun, _SaveSession, _PreparedSave)
from .compose_screens import (ComposeScreensMixin)
from .flow import (FlowMixin)
from .save_commit import (SaveCommitMixin)
from .reports import (ReportsMixin)
from .patch import (PatchMixin)
from .checks_diff import (ChecksDiffMixin)
from .save_plan import (SavePlanMixin)
from .project_load import (ProjectLoadMixin)
from .file_load import (FileLoadMixin)
from .loaded_state import (LoadedStateMixin)
from .workspace_view import (WorkspaceViewMixin)
from .projects import (ProjectsMixin)
from .navigation import (NavigationMixin)
from .a2l_view import (A2lViewMixin)
from .mac_view import (MacViewMixin)
from .issues_checks import (IssuesChecksMixin)
from .hex_view import (HexViewMixin)
from .shell import (ShellMixin)


#: Inc 9b (G3): the ``priority=True`` app actions that must run no app action
#: while the Load dialog is open (LLR-173.2e). The guard reads the whole
#: ``screen_stack`` (S9b-1), so these stay inert even under the palette.
_LOAD_DIALOG_INERT_ACTIONS: frozenset[str] = frozenset(
    {"load_file", "save_project", "focus_palette", "cycle_density"}
)


@dataclass
class _BusyState:
    """S-b: the whole run state — ONE app attribute (``self._busy``)."""

    runs: dict[BusyKey, _BusyRun] = field(default_factory=dict)
    last_gen: int = 0
    file_state: str = "Ready."
    timer: Optional[Timer] = None
    frame: int = 0

#: Inc 12b (S-c, LLR-177.4a): the quit question's title / body / buttons.
_QUIT_TITLE = "Quit?"
_QUIT_BODY = "still working: {label} — wait, or quit after it finishes"
_QUIT_YES, _QUIT_NO = "Quit (y)", "Stay (n)"

#: Inc 1b (S7, G2 r2 q3_body=B): the copy-quit dialog's body — shown when
#: Ctrl+C reaches the shared fallback with nothing selected to copy, or when
#: ``q`` is pressed while idle (R-COPY.16 / R-COPY.23).
_COPY_QUIT_BODY = "Quit the app? Nothing is selected to copy."


class _QuitQuestionScreen(ConfirmQuestionScreen):
    """The quit question (HLR-177b); a subclass so ``action_quit`` can
    recognise it on the stack (Q-c2). It inherits ``AUTO_FOCUS =
    "#confirm_no"``, the ``y`` / ``n`` / ``escape`` bindings, the ``Text``
    labels and the ``_dismissed`` guard (Inc 10). OBS-12b-2 (ruling: the
    safe default carries the emphasis): ``Stay (n)`` is the primary button,
    ``Quit (y)`` the plain one."""

    PRIMARY_BUTTON = "confirm_no"


class _CopyQuitScreen(_QuitQuestionScreen):
    """The copy-quit dialog (Inc 1b, R-COPY.16 / R-COPY.23): the same
    ``Quit?`` shell as :class:`_QuitQuestionScreen`, opened by the shared
    ``action_help_quit`` opener when the operator pressed ``q`` while idle
    or Ctrl+C with nothing selected to copy (G2 r2 body B). It declares no
    methods: ``AUTO_FOCUS = "#confirm_no"``, ``PRIMARY_BUTTON``, the
    ``y`` / ``n`` / ``escape`` bindings, the plain-text labels and the
    one-answer ``_dismissed`` guard all come from the inherited
    ``ConfirmQuestionScreen`` chain (``screens.py``). ``action_quit``'s
    ``isinstance`` stack guard recognises it through ``_QuitQuestionScreen``."""


@dataclass(frozen=True)
class _RightGesture:
    """Inc 1b (S7): the one transient right-click candidate (N3).

    Holds the pre-dispatch snapshot captured on a button-3 ``MouseDown`` —
    the text to copy (or ``None``), the press offset, screen and widget, and
    a ``valid`` flag that a changed-offset ``MouseMove`` clears permanently.
    It is gesture state, not session-action state (TC-B100-09)."""

    text: Optional[str]
    screen_offset: Optional[Offset]
    screen: Optional[Screen]
    widget: Optional[Widget]
    valid: bool

#: The batch-94 (LLR-002.1/.2, LLR-001.2) rail order — the ten shipped entries
#: plus the Check Editor inserted after Patch Editor (the R-1 closure: ``=``
#: binding, ``show=False``) and the Flow Execution entry inserted after Flow
#: Builder (Inc-003, the ``]`` binding — the 12-entry census completes the D5
#: freeze). Built HERE (the sole rail/routing/scan site) rather than in
#: ``rail.py`` so the rework stays inside the increment's four-file SOURCE
#: budget; ``rail.py``'s ``RAIL_ENTRIES`` stays the batch-93 record. The
#: glyph/ascii pairs are the Phase-3 chrome census: ``✔``/``K`` — CHECK-family
#: glyph, ``K`` free in the ASCII table (``C`` belongs to Checks); ``▶``/``>``
#: — the fx_a run glyph (▶ is the spike's running-status glyph), ``>`` free.
#: The guard-host census constants move with this increment (test-side,
#: LLR-002.2 — never before).
RAIL_ENTRIES_B94: tuple[RailEntry, ...] = (
    RAIL_ENTRIES[:6]
    + (RailEntry("check_editor", "✔", "K", "Check Editor"),)
    + RAIL_ENTRIES[6:8]
    + (RailEntry("flow_execution", "▶", ">", "Flow Execution"),)
    + RAIL_ENTRIES[8:]
)


class S19TuiApp(ComposeScreensMixin, FlowMixin, SaveCommitMixin, ReportsMixin, PatchMixin, ChecksDiffMixin, SavePlanMixin, ProjectLoadMixin, FileLoadMixin, LoadedStateMixin, WorkspaceViewMixin, ProjectsMixin, NavigationMixin, A2lViewMixin, MacViewMixin, IssuesChecksMixin, HexViewMixin, ShellMixin, App):
    """Main TUI app with workarea, project management, and views."""

    TITLE = "Hex Edit Tool"
    CSS_PATH = "../styles.tcss"

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
        Binding("ctrl+s", "save_project", "Save project", priority=True),
        ("slash", "focus_find", "Find"),
        ("g", "focus_goto", "Go-to"),
        ("q", "help_quit", "Quit"),
        Binding("l", "load_file", "Load", show=False),
        # Unload-all teardown; per-artifact unload is driven by the Inc-2
        # Workspace "Loaded" panel calling `_apply_unload`. `show=False` keeps
        # the 80-col footer uncrowded (C-13).
        Binding("U", "unload_all", "Unload all", show=False),
        Binding("r", "refresh_files", "Refresh workarea", show=False),
        Binding("o", "open_workarea", "Open workarea", show=False),
        Binding("s", "save_project", "Save project", show=False),
        Binding("p", "load_project", "Projects", show=False),
        Binding("v", "select_variant", "Select variant", show=False),
        Binding("j", "dump_a2l_json", "Dump A2L JSON", show=False),
        # E9 (batch-96): describe the selected A2L tag (CURVE/MAP point
        # table) — A2L-screen scoped inside the action; show=False keeps
        # the footer uncrowded (C-13), discoverable via the `?` help panel.
        Binding("d", "a2l_describe_tag", "Describe tag", show=False),
        Binding("t", "view_reports", "View reports", show=False),
        Binding("x", "operations_view", "Operations", show=True),
        Binding("k", "show_legend", "Legend", show=True),
        # Discoverability: `?` opens Textual's built-in help panel, which lists
        # EVERY active binding (key + description) — so the many show=False keys
        # (rails 1-9, save/load project, dump-json, before/after report, undo/redo,
        # paging) are learnable from the UI. show=True so the Footer advertises it.
        Binding("question_mark", "show_help_panel", "Help", show=True),
        Binding("b", "before_after_report", "Before/After report", show=False),
        Binding("1", "show_screen('workspace')", "Workspace", show=False),
        Binding("2", "show_screen('a2l')", "A2L Explorer", show=False),
        Binding("3", "show_screen('mac')", "MAC View", show=False),
        Binding("4", "show_screen('map')", "Memory Map", show=False),
        Binding("5", "show_screen('issues')", "Issues Report", show=False),
        Binding("6", "show_screen('patch')", "Patch Editor", show=False),
        # batch-94 (R-1 closure, probe-verified `evidence/pdr_rail_key_probe.txt`):
        # the digit row is exhausted at 10 surfaces, so the Check Editor binds
        # `=` — the number row's right-hand neighbour, `show=False` so the
        # footer stays uncrowded (C-13) and discoverable through the `?` help
        # panel. Flow Execution rides `]` (batch-94 Inc-003, the R-1 closure).
        Binding("equals_sign", "show_screen('check_editor')", "Check Editor", show=False),
        Binding("7", "show_screen('diff')", "A2B Diff", show=False),
        Binding("8", "show_screen('flow')", "Flow Builder", show=False),
        Binding("right_square_bracket", "show_screen('flow_execution')", "Flow Execution", show=False),
        Binding("9", "show_screen('checks')", "Checks", show=False),
        Binding("0", "show_screen('crc_designer')", "CRC Designer", show=False),
        ("plus", "page_next_context", "Page+"),
        ("minus", "page_prev_context", "Page-"),
        ("comma", "hex_page_prev", "Hex-"),
        Binding("period", "hex_page_next", "Hex+", key_display="."),
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
        # batch-97 Inc-6 (D10 amended, PC-13): `c` confirms the Flow
        # Execution attention lane. An APP binding gated by `check_action`,
        # so it works wherever the focus is on that screen (arriving with
        # `]` leaves the focus on the rail). An Input still types `c`; a
        # modal blocks it.
        Binding("c", "confirm_attention", "Confirm", show=False),
    ]

    workarea: Path
    current_file: reactive[Optional[LoadedFile]] = reactive(None)
    current_project: Optional[str] = None
    current_a2l_path: Optional[Path] = None
    current_a2l_data: Optional[dict] = None
    #: Monotonic A2L attach generation (batch-102 Inc 2, R-B102-A2L-001/
    #: .004): bumped by the single-writer seam ``_replace_current_a2l`` on
    #: EVERY replacement or clear of the A2L payload, so the enriched-tag
    #: cache key ``(a2l_view_generation, image_generation, mem_size)`` can
    #: never collide across two payloads that reuse one object address.
    #: Declared at class level rather than assigned in ``__init__`` (the
    #: default is immutable and per-instance bumps write through ``+=``)
    #: so the TC-B100-09 source census of ``self.<name> =`` assignments
    #: stays unchanged; the counter is K1-like — monotonic, never reset.
    _a2l_view_generation: int = 0
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
        #: Inc 12a (S-b): the progress indicator's whole run state — one
        #: attribute, main thread only (see ``_BusyState``).
        self._busy = _BusyState()
        #: Inc 12b (S-c): quit confirmed while a session action runs; UI
        #: control state, not session state (TC-B100-09).
        self._quit_pending: bool = False
        #: Inc 1b (S7): the one transient right-click candidate (N3); ``None``
        #: until a button-3 ``MouseDown`` captures a snapshot, and consumed
        #: back to ``None`` on every not-forwarded ``MouseUp``. Gesture state,
        #: not session state (TC-B100-09).
        self._right_gesture: Optional[_RightGesture] = None
        #: Inc 10a E4-R3: the widget a focus landing last put the focus on
        #: because the shown window's declared target was not shown (or, on
        #: A2L, the switch landing of E4-R4); a completed load moves a focus
        #: still sitting there to the target once it is shown. UI focus
        #: state, not session state (TC-B100-09).
        self._focus_landing_fallback: Optional[Widget] = None
        #: Inc 10a (E5, CR-1): ``_hex_view_rows``' memo, ``((image generation,
        #: MAC row set), view rows)``; the invalidation rule is in its docstring.
        self._hex_view_rows_cache: Optional[
            tuple[tuple[int, frozenset[int]], list[int]]
        ] = None
        # N1: the active rail screen, so the Legend modal can scope its rows to
        # what THIS screen paints (updated by ``action_show_screen``).
        self._active_screen_key: str = "workspace"
        #: batch-95 change 4 (LLR-135.6): the rail screen the palette-first
        #: Split / Join / Export window replaced, so its Esc closes back to
        #: exactly where the operator was. ``workspace`` is the pre-change
        #: startup state and the fallback for a direct palette open.
        self._split_join_return_screen: str = "workspace"
        self._a2l_cache_key: Optional[tuple[str, int, int]] = None
        self._a2l_cache_data: Optional[dict[str, Any]] = None
        self._a2l_enriched_tags: list[dict[str, Any]] = []
        #: Enrichment cache key, shape ``(a2l_view_generation,
        #: image_generation, mem_size)`` (batch-102 Inc 2) — never
        #: ``id()``-based; see ``_compute_a2l_enriched_tags``.
        self._a2l_enriched_key: Optional[tuple[int, int, int]] = None
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
        #: Change 1 (HLR-138) — the CRC template LAST loaded through the
        #: CRC Designer's load path, recorded so the save-gather can copy the
        #: template the project USES into ``<project>/templates/`` (the
        #: active-template limb of the recorded predicate in
        #: ``project_gather_service``). ``None`` until a template load
        #: succeeds; a since-deleted path is tolerated by the gather (one
        #: skip finding, never a crash).
        self._last_template_path: Optional[Path] = None
        #: The paste text of the last successful Parse pasted (LED .72 Q2,
        #: pre-ruling 10): Save project clears the Patch Editor's dirty flag
        #: only while the buffer holds no text beyond it
        #: (``_save_clears_panel_flag``). Cleared by the project reset.
        self._parsed_paste_text: Optional[str] = None
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
        #: Per-open Save dialog state (LLR-175.5, ruling Q-1): the one
        #: ``_SaveSession`` computed at the dialog's first ``preview`` (or
        #: ``confirm``), or ``None`` until then and after the Save router
        #: returns.
        self._save_session: Optional[_SaveSession] = None
        #: The prepared save ``_confirm_project_save`` approved, holding the
        #: painted plan object (proposal P-3); read and cleared by the Save
        #: router's identity match.
        self._save_confirmed: Optional[_PreparedSave] = None
        #: The last preview the dialog painted (A11-08);
        #: ``_confirm_project_save`` compares the fresh preview against it.
        self._save_painted_preview: Optional[SavePreview] = None
        #: Most recent manifest verify outcome (LLR-004.2), published by
        #: ``_write_and_verify_manifest`` so the save handler can re-paint a
        #: MISMATCH as the newest status line after the success line.
        self._last_manifest_verify_result: Optional[ManifestVerifyResult] = None
        #: Most recent A↔B comparison result, retained so the diff-report
        #: trigger (LLR-005.4) can report the same comparison the panel shows.
        self._diff_last_result: Optional[Any] = None
        #: The check spec loaded into the A2B Diff dropdown (batch-94,
        #: LLR-010.1/.2) — the document whose declared fields ride the next
        #: emitted diff report as the ``## Checks`` addendum. ``None`` is
        #: the "no check spec" state (the dropdown's blank option); only a
        #: clean ``kind="check"`` document is ever stashed here.
        self._diff_check_spec: Optional[ChangeDocument] = None
        self._diff_check_spec_name: str = ""
        #: Monotonic count of COMPLETED A↔B compare requests (batch-78 Inc-2,
        #: gate review F7). Incremented on EVERY exit path of
        #: ``on_ab_diff_panel_compare_requested`` — refusal, load failure,
        #: success and exception alike — so it is a TOTAL completion signal.
        #: ``_diff_last_result`` cannot serve this purpose: it is written only
        #: on the non-refused branch, so waiting on it would hang forever on a
        #: refusal instead of reporting one.
        #:
        #: Why it exists at all: the handler became a coroutine that suspends
        #: on an awaited widget removal, and ``Pilot.pause()`` waits for
        #: message-queue IDLENESS. A handler parked on ``AwaitRemove`` has
        #: already dequeued its message, so ``pause()`` returns while it is
        #: still suspended and a reader sees the un-rendered panel. Waiting on
        #: this counter waits on the handler, not on the queue.
        self._diff_compare_generation: int = 0
        #: Variant id to stamp onto the next applied primary ``LoadedFile``.
        #: Set on the main thread immediately before a load dispatch and
        #: consumed by ``_apply_prepared_load`` on the main thread, so the
        #: parse worker signature stays untouched and the worker never reads
        #: this field (LLR-005.4 thread contract). Cleared on load failure.
        self._pending_variant_id: Optional[str] = None
        #: The announcement of the last project load (LLR-178.1): what the
        #: Load-result panel shows, kept for the session.
        self._last_load_announcement: Optional[LoadAnnouncement] = None
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
        # batch-94: the rail carries the 12-entry B94 order (Check Editor
        # after Patch Editor, Flow Execution after Flow Builder) — see
        # `RAIL_ENTRIES_B94`.
        yield Horizontal(
            Container(Rail(entries=RAIL_ENTRIES_B94, active="workspace"), id="rail_slot"),
            Container(
                self._compose_screen_workspace(),
                self._compose_screen_a2l(),
                self._compose_screen_mac(),
                self._compose_screen_map(),
                self._compose_screen_issues(),
                self._compose_screen_patch(),
                self._compose_screen_check_editor(),
                self._compose_screen_diff(),
                self._compose_screen_flow(),
                self._compose_screen_flow_execution(),
                self._compose_screen_checks(),
                self._compose_screen_crc_designer(),
                self._compose_screen_split_join(),
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
            # LLR-120.3 -- the context shares `#status_text`'s ROW rather than
            # taking one of its own. The bar is 7 rows on all 10 screens
            # (measured 116x7); an eighth row costs 1 row app-wide against Lane
            # 1's 3-row reclaim, and the diff pane has 2 content rows to begin
            # with. Two SIBLINGS in one `Horizontal`, not one shared widget:
            # `set_status` / `set_file_status` own `#status_text` and would
            # clobber the context on their next write.
            Horizontal(
                deps.Label("Ready.", id="status_text", markup=False),
                # LLR-120.4: written only via `safe_text`, so this constructor
                # arg is the sentinel, never file-derived text.
                deps.Label("", id="status_context", markup=False),
                id="status_line",
            ),
            # OBS-12a-1: no Textual ETA beside the seam's elapsed time.
            ProgressBar(total=100, id="progress_bar", show_eta=False),
            # batch-33 (LLR-051.8, C-17): the log lines render FILE-DERIVED
            # text (issue messages embedding verbatim {kind!r}/{fmt!r}/... ,
            # check reasons) — markup=False at CONSTRUCTION is the single
            # funnel scrub, applied AFTER the 50-char cap in
            # `_append_log_line` (never pre-escape: the cap would bisect
            # escape sequences). Closes the pre-existing CHG-KIND-UNKNOWN
            # class (five sibling messages). No caller uses intended markup
            # (repo-wide grep: zero Rich tags reach set_status).
            deps.Label("", id="log_line_1", markup=False),
            deps.Label("", id="log_line_2", markup=False),
            deps.Label("", id="log_line_3", markup=False),
            deps.Label("", id="log_line_4", markup=False),
            id="workspace_status_bar",
        )
        # batch-97 Inc-8 (HLR-150, D26): the two-row key bar replaces the
        # one-row Footer — row 1 the global keys, row 2 the active window's.
        yield KeyBar(id="key_bar")

    def on_flow_execution_panel_external_step_confirmed(
        self, event: "FlowExecutionPanel.ExternalStepConfirmed"
    ) -> None:
        """Re-run ONE lane with its confirmed external steps (spec v3).

        Summary:
            The operator confirmed the lane's waiting external step (its
            Confirm or ``c``): the human ran the step OUTSIDE the app and the
            MANDATORY log + the output file exist. Build one confirmation per
            block the lane has confirmed in its current wait sequence
            (:meth:`FlowExecutionPanel.confirmed_blocks`, batch-97 I-7 (d)),
            each from its own block's declared fields — so a lane with two
            external steps reaches its end instead of waiting again at its
            first (LED-2026-10-19-batch-97.29) — re-run JUST that lane
            through the real ``run_chain_set`` and hand the outcome back to
            :meth:`FlowExecutionPanel.apply_confirmed_run`. Every exit ends
            in ``apply_confirmed_run`` or ``render_confirm_error`` (D14): the
            panel disabled Run and every Confirm before posting, and both
            painters enable them again.

        Args:
            event (FlowExecutionPanel.ExternalStepConfirmed): Carries the
                lane index and the external-step block index.
        """
        from ..services.flow_execution_service import (
            CHAIN_RUN_CONFIRM_RERUN,
            ChainSpec,
            run_chain_set,
        )
        from ..services.flow_model import (
            ExternalStepBlock,
            ExternalStepConfirmation,
            FlowContext,
        )

        panel = self.query_one("#fx_panel", FlowExecutionPanel)
        lane_index, block_index = event.lane_index, event.block_index
        project_dir = self._active_project_dir()
        if project_dir is None:
            panel.render_confirm_error(
                lane_index, "no project loaded - load or save a project first"
            )
            return
        refused = (
            f"confirm refused - lane {lane_index + 1} no longer waits at "
            f"block {block_index + 1}"
        )
        specs = panel.lane_specs()
        if lane_index >= len(specs):
            panel.render_confirm_error(lane_index, refused)
            return
        spec = specs[lane_index]
        blocks = spec.flow.blocks
        confirmed = panel.confirmed_blocks(lane_index)
        if (
            block_index not in confirmed
            or block_index >= len(blocks)
            or not isinstance(blocks[block_index], ExternalStepBlock)
        ):
            panel.render_confirm_error(lane_index, refused)
            return
        confirmations = {
            index: ExternalStepConfirmation(
                block_index=index,
                log_ref=blocks[index].log_ref,
                source_path=blocks[index].output_path,
            )
            for index in confirmed
            if index < len(blocks) and isinstance(blocks[index], ExternalStepBlock)
        }
        chains = [
            ChainSpec(
                name=spec.name,
                template=spec.template,
                flow=spec.flow,
                bindings=dict(spec.bindings),
            )
        ]
        ctx = FlowContext(
            project_dir=project_dir,
            external_confirmations=confirmations,
        )
        try:
            record = run_chain_set(
                chains,
                ctx,
                mode=CHAIN_RUN_CONFIRM_RERUN,
                set_name=str(self.query_one("#fx_set_name", Input).value),
            )
        except Exception as exc:  # noqa: BLE001 - every raise becomes one line
            panel.render_confirm_error(lane_index, fx_run_error_line(exc))
            return
        failed = panel.apply_confirmed_run(lane_index, record)
        if failed:
            self.set_status(failed)

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
        # batch-48 LLR-081.3 (writer census, site 4 of 4 — the INITIAL render).
        # ⚠ The LLR names THREE sites and all three are ACTION sites, so none
        # of them fires before the analyst's first action: the Patch Editor
        # opened blank, and "blank" is not the empty state — it is nothing. The
        # empty state (`0 back / 0 fwd / 0-of-20`) is exactly the state a fresh
        # screen is in and it must PAINT. This site is app-side rather than in
        # `PatchEditorPanel.on_mount` (which is where the sibling
        # `_refresh_variant_scope_line` / `_refresh_paste_gauge` mount-time
        # renders live, for this same never-mount-blank reason) because the
        # panel is a view: it cannot know `_HISTORY_MAX` without importing the
        # service layer, and a panel-side default would have to invent a bound
        # — rendering `0/0`, a wrong capacity on the surface that exists to
        # report capacity.
        #
        # This is the MJ-1 shape exactly: that census also counted three
        # `refresh_entries` sites and missed a mount-time fourth.
        self.query_one("#patch_editor_panel", PatchEditorPanel).set_undo_redo_enabled(
            self._change_service.document.source_path is None,
            self._change_service.history_depths(),
        )
        # Keep startup focus off the command-bar inputs so the unmodified
        # single-key bindings (rail digits 1-8, `/`, `g`, paging) fire
        # normally until the user explicitly focuses an input (LLR-004.5 —
        # suppression applies only *while* a command-bar input has focus).
        self._focus_activity_rail()
        if self.load_path:
            self.logger.info("Startup load requested: %s", self.load_path)
            self._load_path_from_user_input(self.load_path)

    #: Rail screen-key -> ``#workspace_body`` child container id (LLR-002.1).
    #: Ordered Workspace, A2L, MAC, Map, Issues, Patch, Check Editor, Diff,
    #: Flow, Flow Execution, Checks, CRC Designer — the batch-94 rail order
    #: (RAIL_ENTRIES_B94; Check Editor after Patch Editor LLR-002.1, Flow
    #: Execution after Flow Builder US-007).
    SCREEN_CONTAINER_IDS = {
        "workspace": "screen_workspace",
        "a2l": "screen_a2l",
        "mac": "screen_mac",
        "map": "screen_map",
        "issues": "screen_issues",
        "patch": "screen_patch",
        "check_editor": "screen_check_editor",
        "diff": "screen_diff",
        "flow": "screen_flow",
        "flow_execution": "screen_flow_execution",
        "checks": "screen_checks",
        "crc_designer": "screen_crc_designer",
    }

    #: LLR-119.1 — rail screen-key -> (find input id, go-to input id), or
    #: ``None`` where the screen owns neither.
    #:
    #: **Every one of `SCREEN_CONTAINER_IDS`' ten keys appears here, and the
    #: seven `None`s are the point.** The map could have listed only the three
    #: owners and been shorter; then its key set would be the implementation's
    #: own opinion of who owns an input, and an acceptance quantifying over it
    #: would certify a completeness the code does not have (C-40 limb 2). Keyed
    #: on all ten, `set(_FIND_GOTO_INPUTS) == set(SCREEN_CONTAINER_IDS)` is a
    #: real assertion, and a screen added later without a decision here fails it
    #: instead of silently joining the notice path. **That assertion is
    #: `TC-B79-03`** — it was named here from batch-78 onward and did not exist
    #: until batch-79 Inc-11, when the merge gate found the prose claiming a
    #: mechanism no test implemented.
    #:
    #: **Routing is by SCREEN KEY, never by widget presence.**
    #: ``action_show_screen`` swaps a ``hidden`` class and nothing unmounts
    #: (P-10), so all eight inputs resolve on every screen — a presence-based
    #: implementation is green while wrong. That is not hypothetical: today,
    #: with an image loaded and A2L active, a find writes into the WORKSPACE
    #: ``#search_input`` and searches the workspace map.
    #:
    #: The owning set is `{workspace, a2l, mac}` — n=3 under the normative
    #: derivation (an input id matching ``(search|goto)_input$``). A bare "any
    #: Input in the container" count gives **7** (`patch` 5, `diff` 3, `flow` 1,
    #: `crc_designer` 13 inputs, none of them a find or go-to), so the two
    #: honest derivations disagree and only the stated pattern is a definition.
    _FIND_GOTO_INPUTS: "dict[str, Optional[tuple[str, str]]]" = {
        "workspace": ("search_input", "goto_input"),
        "a2l": ("alt_search_input", "alt_goto_input"),
        "mac": ("mac_search_input", "mac_goto_input"),
        "map": None,
        "issues": None,
        "patch": None,
        "check_editor": None,
        "diff": None,
        "flow": None,
        "flow_execution": None,
        "checks": None,
        "crc_designer": None,
    }

    #: The six find/goto input ids, DERIVED from the map above rather than
    #: re-listed. A hand-written second copy is a set that can disagree with the
    #: one the routing uses, and `Escape` would then release an input the
    #: routing can focus, or vice versa.
    _FIND_GOTO_INPUT_IDS = frozenset(
        input_id
        for pair in _FIND_GOTO_INPUTS.values()
        if pair is not None
        for input_id in pair
    )

    #: N1: which ``legend.LEGEND_TABLE`` section(s) each rail screen actually
    #: paints, so the Legend modal shows only those rows. A screen absent here
    #: (Workspace / Flow / CRC-Designer) falls back to the FULL table (AC-3) —
    #: never an empty legend. The section keys are LEGEND_TABLE artifact keys
    #: (``A2L`` / ``MAC`` / ``Issues`` / ``Hex``); the row colours still
    #: round-trip through the frozen ``SEVERITY_CLASS_MAP`` (read-only).
    _SCREEN_LEGEND_SECTIONS: Dict[str, tuple[str, ...]] = {
        # N8: Workspace is example-only (LLR-N8-1.2) and Map renders the entropy
        # band key, not the LEGEND_TABLE["Hex"] severity rows (LLR-N8-3.3) — both
        # map to () so `compose` shows zero severity rows. `patch`/`diff` keep
        # ("Hex",) (out of N8 scope); `flow` stays unmapped → full-table fallback.
        "workspace": (),
        "a2l": ("A2L",),
        "mac": ("MAC",),
        "issues": ("Issues",),
        "map": (),
        "patch": ("Hex",),
        "diff": ("Hex",),
        "checks": ("Issues",),
    }

    #: LLR-166.1 — the per-window focus target: the named, non-text widget a
    #: load tail lands the keyboard focus on (HLR-166, CW-U-2). Declared per
    #: window and asserted 1:1 against the window registry — every key of
    #: ``SCREEN_CONTAINER_IDS`` plus the palette-only Split / Join / Export
    #: window (``_active_screen_key == "split_join"`` while it rides the rail
    #: body) — by TC-B100-12, so a window added to the registry without a
    #: declared target, a dropped window, or a text-input target fails the
    #: census instead of silently joining the re-home path. Every target must
    #: be focusable: ``Screen.set_focus`` silently ignores a widget whose
    #: ``can_focus`` is False (the census asserts this too), so the Map
    #: target is the panel itself with ``can_focus`` declared at compose and
    #: the Diff target is its always-painted Compare button. On the Map
    #: window the post-load LANDING is not the panel but the region row
    #: LLR-116.5 auto-selects and focuses (LED .58 (a)): the panel stays
    #: the declared target — the empty-state/fallback landing — and the
    #: row, an id-less widget, is the Map window's landing by HLR-166's
    #: "named widget" ledger line ("the selected region row").
    _FOCUS_TARGETS: "dict[str, str]" = {
        "workspace": "files_list",
        "a2l": "a2l_tags_list",
        "mac": "mac_records_list",
        "map": "memory_map_panel",
        "issues": "validation_issues_groups",
        "patch": "patch_editor_panel",
        "check_editor": "check_editor_panel",
        "diff": "diff_compare_button",
        "flow": "flow_panel",
        "flow_execution": "fx_panel",
        "checks": "checks_grouped",
        "crc_designer": "crc_designer_panel",
        "split_join": "sje_table",
    }

    #: Inc 10a E4-R4 (I-D16): where a window switch lands instead of the
    #: declared target when that target's own bindings shadow the window's
    #: paging keys. The A2L tag table handles PgDn / PgUp itself (LLR-042.1),
    #: so a landing there would stop PgDn paging the A2L Explorer right
    #: after ``2`` (R-TUI-020.1); the window's ``?`` chip leads its header
    #: and binds Enter only. The MAC record table does the same after ``3``
    #: (E4-R6, I-D18); that window has no chip, so the switch lands on its
    #: first focusable control, the Page Prev button (Enter only). Load
    #: tails still land on ``_FOCUS_TARGETS``.
    _SWITCH_LANDING_TARGETS: "dict[str, str]" = {
        "a2l": "window_help_a2l",
        "mac": "mac_page_prev_button",
    }

    #: Every window container a focused widget can sit in: the registry's
    #: containers plus the Split / Join / Export window. Derived from
    #: ``SCREEN_CONTAINER_IDS`` rather than re-listed, so the two sets can
    #: never disagree (the same C-40 completeness argument as
    #: ``_FIND_GOTO_INPUT_IDS``).
    _WINDOW_CONTAINER_IDS = frozenset(SCREEN_CONTAINER_IDS.values()) | {
        "screen_split_join"
    }

    #: One extra command-palette command outside ``BINDINGS``: the viewer
    #: page-size settings menu lost its ``#view_bar`` trigger in increment 2
    #: (G-1) — it is resurfaced here so it stays keyboard-reachable (C-9).
    #: batch-95 change 4 (HLR-135, ruling Q6/7a): the Split / Join / Export
    #: screen is palette-first and binds NO rail key — its one palette entry
    #: (named exactly "Split / Join / Export") opens it.
    EXTRA_PALETTE_ENTRIES = (
        ("Viewer settings", "open_settings_menu"),
        ("Split / Join / Export", "open_split_join_export"),
    )

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Gate app actions by the active window (batch-97 I-11, D10),
        by the Load dialog (Inc 9b, LLR-173.2e), by the replace
        question (Inc 10, LLR-174.2h) and by the Save project dialog
        (Inc 11, LLR-175.3g).

        Summary:
            ``confirm_attention`` (the ``c`` key and its ^K palette entry)
            runs only while Flow Execution is the active window — off it the
            key does nothing and the binding is not active. Inc-8 (D28):
            ``+`` / ``-`` page only on A2L and MAC, and ``,`` / ``.`` only
            on Workspace — elsewhere they would page a hidden view. Inc 9b
            (G3) / Inc 10 (S-f) / Inc 11 (LLR-175.3g): the four
            ``priority=True`` actions in ``_LOAD_DIALOG_INERT_ACTIONS`` are
            inert while any screen on the stack is a ``LoadDialog``, a
            ``ConfirmQuestionScreen`` or a ``SaveProjectScreen`` (the
            whole-stack guard, S9b-1). Every other action falls through to
            Textual's own check.

        Args:
            action (str): The action name.
            parameters (tuple): The action's parameters.

        Returns:
            Optional[bool]: ``False`` for an action off its window, else
            what ``App.check_action`` returns.
        """
        if action in _LOAD_DIALOG_INERT_ACTIONS and any(
            isinstance(s, (LoadDialog, ConfirmQuestionScreen, SaveProjectScreen))
            for s in self.screen_stack
        ):
            return False
        if action == "confirm_attention":
            return self._active_screen_key == "flow_execution"
        if action in ("page_next_context", "page_prev_context"):
            return self._active_screen_key in ("a2l", "mac")
        if action in ("hex_page_prev", "hex_page_next"):
            return self._active_screen_key == "workspace"
        return super().check_action(action, parameters)

    def action_show_help_panel(self) -> None:
        """
        Summary:
            Toggle Textual's built-in help panel (N6). The footer-visible ``?``
            binding routes here (its action name stays ``show_help_panel`` so the
            discoverability contract — key/label/visibility — is unchanged). The
            stock ``App.action_show_help_panel`` only MOUNTS the panel, leaving no
            keyboard way to dismiss it; this override makes ``?`` an on/off toggle:
            press once to show, press again to hide.

        Returns:
            None

        Data Flow:
            - Query the mounted ``HelpPanel``; if present, delegate to the stock
              ``action_hide_help_panel`` (removes it), otherwise to the stock
              ``super().action_show_help_panel`` (mounts it). No panel state is
              re-implemented here.

        Dependencies:
            Uses:
                - ``HelpPanel`` (presence probe)
                - ``App.action_show_help_panel`` / ``App.action_hide_help_panel``
            Used by:
                - The ``question_mark`` key binding
        """
        if self.query(HelpPanel):
            self.action_hide_help_panel()
        else:
            super().action_show_help_panel()

    # Screens that own both real content and an `EmptyStatePanel`; the panel
    # is shown only while no file is loaded (LLR-002.3). Each tuple is the
    # screen container id and the id of its real-content child to hide.
    _EMPTY_STATE_SCREENS = (
        ("screen_workspace", "workspace_panes"),
        ("screen_issues", "issues_content"),
        ("screen_map", "map_content"),
        ("screen_checks", "checks_content"),
    )

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

    def watch_current_file(self) -> None:
        """
        Summary:
            Refresh the palette-first Split / Join / Export window
            (batch-95 change 4) whenever the loaded image changes — its
            segment sources (the image's ranges, the coverage sweep, the
            default stem) are a live VIEW over ``current_file``, so a load
            or an unload while the window is open must re-plan the band,
            not leave the previous image's rows addressable.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Re-resolves ``#screen_split_join`` and calls its
              ``refresh_window``; a missing tree (headless tests assigning
              ``current_file`` before mount) is tolerated, matching
              ``_apply_empty_state``'s documented no-op.

        Dependencies:
            Uses:
                - ``SplitJoinWindow``
            Used by:
                - The ``current_file`` reactive on every install/unload.
        """
        # batch-97 Inc-8 (PC-23): the key bar dims the image keys by this.
        self.refresh_bindings()
        try:
            window = self.query_one("#screen_split_join", SplitJoinWindow)
        except Exception:
            return
        window.refresh_window()

    #: The separator between the two halves of `#status_context`.
    _CONTEXT_SEPARATOR = "  |  "

    #: Mirrors `styles.tcss`'s `#workspace_status_bar #status_context
    #: { max-width: 70% }`. The cell is `width: auto` up to that share, so this
    #: share IS the budget the two halves must fit inside. Kept as a named
    #: constant rather than a literal because it is a COUPLING to the
    #: stylesheet: `TC-B79-01` asserts the two agree, so changing one without
    #: the other reddens instead of silently clipping again.
    _CONTEXT_MAX_SHARE = 0.70

    #: Last-resort budget, reached only when the terminal reports a width at or
    #: below `_CONTEXT_BAR_INSET`. 53 is the measured cell width at the
    #: narrowest supported terminal, 80x24.
    #:
    #: ⚠️ Recorded rather than claimed: this is **very nearly dead code**, and
    #: the comment it replaces was false twice over. It said "used when the
    #: terminal has no resolved width yet (pre-mount)" -- measured, an unmounted
    #: `App.size` falls through to `console.size` and returns `Size(80, 25)`,
    #: never 0, so the pre-mount path does not reach here. And the live path
    #: cannot either: `update_project_labels` early-returns before the composer
    #: when `#status_context` is unresolvable. It also called 53 "the SAFE end
    #: of the range"; at the only width that can reach it (<= 4 columns) a
    #: 53-column budget is the OPTIMISTIC end. Kept as a defined value rather
    #: than deleted, because the alternative is an unbounded string, but it is
    #: not a fallback anyone should reason from.
    _CONTEXT_FALLBACK_BUDGET = 53

    #: Columns of app chrome between the TERMINAL width and
    #: `#workspace_status_bar`'s width. Measured at all three supported sizes:
    #: 80 -> 76, 120 -> 116, 160 -> 156.
    #:
    #: The budget is derived from the TERMINAL width rather than by querying the
    #: bar, and that is not a shortcut -- it is the only current value at the
    #: moment it is needed. During a resize the bar's cached `size.width` is
    #: STALE: executed at 160x40 -> 80x24, the deferred recompose read
    #: `bar=156, #status_context=91` while `App.size.width` already read `80`.
    #: Budgeting off the bar recomposed to the size being LEFT, which is why the
    #: first version of the resize fix changed nothing observable.
    #:
    #: `TC-B79-02` asserts this inset against the live tree at all three sizes,
    #: so a layout change reddens instead of silently re-clipping.
    _CONTEXT_BAR_INSET = 4

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

    def copy_to_clipboard(self, text: str) -> None:
        """
        Summary:
            Schedule the OS clipboard tail once for a non-empty copy, or
            raise :class:`textual.actions.SkipAction` for ``""`` (Inc 1b,
            R-COPY.1 … R-COPY.10, I-1). An empty string raises BEFORE any
            coroutine or worker is built — a normal return would mark the
            Ctrl+C binding handled and suppress the idle copy-quit fallback
            (R-COPY.16). A non-empty string schedules
            ``_mirror_and_write_os_clipboard(self, text)`` exactly once with
            the original, untruncated text; the tail alone owns the app
            clipboard mirror, the 65,536-character cap, the OS write, the
            NUL refusal (R-COPY.25) and the result notice. Text-box
            copy/cut still calls the tail directly, never this override.

        Args:
            text (str): The original, untruncated text to copy.

        Returns:
            None

        Raises:
            textual.actions.SkipAction: When ``text == ""``.

        Data Flow:
            - ``Screen.action_copy_text`` / stock ``TextArea.action_copy``
              call this override for Ctrl+C and F7-style copies; ``on_event``
              calls it once for a valid button-3 release.

        Dependencies:
            Uses:
                - ``_mirror_and_write_os_clipboard``
                - ``App.run_worker`` (inherited)
            Used by:
                - Textual ``Screen.action_copy_text`` / stock ``TextArea``
                - ``S19TuiApp.on_event``
        """
        if text == "":
            raise SkipAction
        self.run_worker(deps._mirror_and_write_os_clipboard(self, text))

    async def on_event(self, event: events.Event) -> None:
        """
        Summary:
            Deferred right-click capture (Inc 1b, R-COPY.11 … R-COPY.15,
            E3-01): snapshot on button-3 ``MouseDown``, invalidate on any
            changed-offset ``MouseMove``, and copy once on a valid matching
            ``MouseUp`` — always before the single ``super().on_event``
            forward so the toolkit still clears the selection afterwards.

        Args:
            event (events.Event): The driver event reaching the app entry.

        Returns:
            None

        Data Flow:
            - Every not-forwarded ``MouseDown`` first clears any old
              ``_right_gesture``; button 3 stores a fresh snapshot with
              ``valid=True`` (no copy on press).
            - A ``MouseMove`` whose ``screen_offset`` differs permanently
              clears ``valid`` via ``replace`` (exit-and-return does not
              restore it).
            - Every not-forwarded ``MouseUp`` consumes/clears the candidate
              before a possible copy; a valid button-3 release with the same
              offset/screen/widget and non-empty text calls
              ``copy_to_clipboard`` once.
            - Every path ends with exactly one ``await super().on_event``.

        Dependencies:
            Uses:
                - ``_RightGesture`` / ``replace``
                - ``S19TuiApp._right_click_text``
                - ``S19TuiApp.copy_to_clipboard``
            Used by:
                - Textual driver event dispatch
        """
        if isinstance(event, events.MouseDown) and not event.is_forwarded:
            self._right_gesture = None
            if event.button == 3:
                screen = self.screen
                try:
                    widget, _ = screen.get_widget_at(event.screen_x, event.screen_y)
                except Exception:
                    widget = None
                self._right_gesture = _RightGesture(
                    text=self._right_click_text(event.screen_x, event.screen_y),
                    screen_offset=event.screen_offset,
                    screen=screen,
                    widget=widget,
                    valid=True,
                )
        elif isinstance(event, events.MouseMove):
            candidate = self._right_gesture
            if candidate is not None and event.screen_offset != candidate.screen_offset:
                self._right_gesture = replace(candidate, valid=False)
        elif isinstance(event, events.MouseUp) and not event.is_forwarded:
            candidate = self._right_gesture
            self._right_gesture = None
            if (
                candidate is not None
                and event.button == 3
                and candidate.valid
                and candidate.text
                and candidate.screen is self.screen
                and candidate.screen_offset == event.screen_offset
            ):
                try:
                    widget, _ = self.screen.get_widget_at(event.screen_x, event.screen_y)
                except Exception:
                    widget = None
                if widget is candidate.widget:
                    self.copy_to_clipboard(candidate.text)
        await super().on_event(event)

    def action_help_quit(self) -> None:
        """
        Summary:
            Shared q / Ctrl+C fallback (Inc 1b, R-COPY.6, .16, .19, .20,
            .23): with a running session action it opens the existing busy
            ``_QuitQuestionScreen`` (R-QUIT.1); otherwise it opens exactly
            one ``_CopyQuitScreen`` with body B. Both use ``_answer_quit``.

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``q`` reaches this via the ``help_quit`` binding (selection
              present or absent); Ctrl+C reaches it only after a copy raised
              ``SkipAction`` for nothing selected.
            - The modal binding chain (C4) already keeps q / Ctrl+C away
              while any dialog is open, so no explicit modal-stack branch is
              added and no second dialog is stacked.

        Dependencies:
            Uses:
                - ``_running_session_action``
                - ``_QuitQuestionScreen`` / ``_CopyQuitScreen``
                - ``_answer_quit``
            Used by:
                - the ``q`` binding and the toolkit Ctrl+C fallback
        """
        run = self._running_session_action()
        if run is not None:
            self.push_screen(
                _QuitQuestionScreen(
                    _QUIT_TITLE,
                    _QUIT_BODY.format(label=run.label),
                    _QUIT_YES,
                    _QUIT_NO,
                ),
                self._answer_quit,
            )
            return
        self.push_screen(
            _CopyQuitScreen(_QUIT_TITLE, _COPY_QUIT_BODY, _QUIT_YES, _QUIT_NO),
            self._answer_quit,
        )

    def action_quit(self) -> None:
        """S-c: quit now, or ask while a session action runs (HLR-177b)."""
        run = self._running_session_action()
        if run is None:
            self.exit()
            return
        # Q-c2: ``ctrl+q`` is a priority binding and ``quit`` is not inert,
        # so it reaches here under the question — ignore it.
        if any(isinstance(s, _QuitQuestionScreen) for s in self.screen_stack):
            return
        self.push_screen(
            _QuitQuestionScreen(
                _QUIT_TITLE,
                _QUIT_BODY.format(label=run.label),
                _QUIT_YES,
                _QUIT_NO,
            ),
            self._answer_quit,
        )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="S19/HEX/MAC TUI Viewer")
    parser.add_argument("--load", help="Optional path to load at startup")
    args = parser.parse_args()
    load_path = Path(args.load) if args.load else None
    app = S19TuiApp(load_path=load_path)
    app.run()
