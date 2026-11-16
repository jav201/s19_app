"""s19_app.tui.app.compose_screens — S19TuiApp mixin: compose_screens (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from textual.containers import Container, Horizontal, ScrollableContainer
from textual.widgets import Button, DataTable, ListView, Static
from ..os_clipboard_input import OsClipboardInput
from ..flow_screens import FlowBuilderPanel, FlowExecutionPanel
from ..screens_directionb import (
    AbDiffPanel,
    CheckEditorPanel,
    EmptyStatePanel,
    LoadedArtifactsPanel,
    MemoryMapPanel,
    PatchEditorPanel,
)
from ..crc_designer_view import CrcDesignerPanel
from ..issues_view import GroupedIssuesPanel
from ..checks_view import GroupedChecksPanel
from ..open_folder_chip import OpenFolderChip, titled_header
from ..window_help import WindowHelpChip, WindowSection
from ..segment_split_view import SplitJoinWindow
from . import deps
from .shared import (_CopyRowTable, A2LTagTable, A2LDetailCard)


class ComposeScreensMixin:

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
            - A persistent ``LoadedArtifactsPanel`` (``#loaded_panel``, unload
              feature Inc-2) is composed OUTSIDE ``#workspace_panes`` so it stays
              visible in the no-file empty state; ``_refresh_loaded_panel``
              drives its ``render_slots`` after every load and unload.

        Dependencies:
            Uses:
                - ``EmptyStatePanel`` / ``LoadedArtifactsPanel``
            Used by:
                - ``compose``
        """
        _left_pane = Container(
            Button("Load project (p)", id="ws_load_project_button"),
            deps.Label("Workarea Files", id="files_title"),
            ListView(id="files_list"),
            deps.Label("Data Sections", id="sections_title"),
            ListView(id="sections_list"),
            id="ws_left",
            classes="db-pane",
        )
        _center_pane = Container(
            deps.Label("Hex View", id="hex_title"),
            Container(
                OsClipboardInput(placeholder="Search ASCII text", id="search_input"),
                Button("Find Next", id="search_button"),
                OsClipboardInput(placeholder="Goto 0xADDR", id="goto_input"),
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
            deps.Label("Coverage Stats", id="ws_stats_title"),
            Static("", id="ws_stats", markup=False),
            deps.Label("Context", id="a2l_title"),
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
        # The persistent "Loaded" panel (unload feature Inc-2) sits OUTSIDE
        # `#workspace_panes` so `_apply_empty_state` (which hides the panes with
        # no file) never hides it — it is the always-visible load-state readout.
        # The change-3 header row (title + the `?` usage-help chip, HLR-140)
        # leads the screen like every other window; the panes hold the 1fr
        # remainder.
        return WindowSection(
            "workspace",
            titled_header("Workspace", help_button=WindowHelpChip("workspace")),
            _memstrip,
            LoadedArtifactsPanel(),
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
        _issues_list_stack = Container(
            GroupedIssuesPanel(id="validation_issues_groups"),
            id="issues_list_stack",
        )
        # Author-constant border titles (batch-49, LLR-082.4) — never
        # file-derived (C-17); the matching border/title CSS lives in styles.tcss.
        _issues_list_stack.border_title = "Issues"
        _issues_list_stack.border_subtitle = "grouped"
        _issues_hex_pane = Static("", id="issues_hex_pane", markup=False)
        _issues_hex_pane.border_title = "Hex Peek"
        _issues_content = Container(
            Container(
                Button("Issues: All", id="issues_filter_all"),
                Button("Errors", id="issues_filter_error"),
                Button("Warnings", id="issues_filter_warning"),
                Button("Legend", id="issues_legend_button"),
                id="validation_issues_filters",
            ),
            Static("", id="issues_severity_strip", markup=False),
            Container(
                _issues_list_stack,
                _issues_hex_pane,
                id="issues_columns",
            ),
            deps.Label("", id="validation_issues_summary"),
            id="issues_content",
        )
        return Container(
            deps.Label("Issues Report", classes="db-screen-title"),
            _issues_content,
            EmptyStatePanel(),
            id="screen_issues",
            classes="db-screen hidden",
        )

    def _compose_screen_checks(self) -> Container:
        """
        Summary:
            Build the dedicated CHECKS rail screen (``#screen_checks``, the
            ninth activity-rail screen — batch-49 LLR-083.5) as a read-only
            mirror of the last check run: an aggregate pass/fail/uncheckable
            strip above a grouped-by-outcome list beside a hex peek pane.
            Modelled on ``_compose_screen_issues``; hidden at startup.

        Args:
            None

        Returns:
            Container: ``#screen_checks`` holding the ``Checks`` header row
            (title + the ``📂 Open checks/`` chip, HLR-139 / LLR-148.10), a
            ``#checks_content`` container (the ``#checks_aggregate_strip``
            ``Static`` above a ``#checks_columns`` horizontal split whose left
            ``GroupedChecksPanel`` (``#checks_grouped``) sits beside the hex
            peek ``#checks_hex_pane``), and an ``EmptyStatePanel``.

        Data Flow:
            - ``update_checks_view`` drives ``#checks_grouped`` +
              ``#checks_aggregate_strip`` from ``_change_service`` (LLR-084.3).
            - While no ``LoadedFile`` is present ``_apply_empty_state`` shows
              the ``EmptyStatePanel`` and hides ``#checks_content``
              (LLR-084.6).

        Dependencies:
            Uses:
                - ``GroupedChecksPanel`` / ``EmptyStatePanel``
            Used by:
                - ``compose``
        """
        # Author-constant border titles (batch-49, LLR-083.5 / R-4) — never
        # file-derived (C-17); the matching border/title CSS lives in
        # styles.tcss (a titled pane renders its title only with a border).
        _checks_grouped = GroupedChecksPanel(id="checks_grouped")
        _checks_grouped.border_title = "Checks"
        _checks_grouped.border_subtitle = "grouped"
        _checks_hex_pane = Static("", id="checks_hex_pane", markup=False)
        _checks_hex_pane.border_title = "Hex Peek"
        _checks_content = Container(
            Static("", id="checks_aggregate_strip", markup=False),
            Container(
                _checks_grouped,
                _checks_hex_pane,
                id="checks_columns",
            ),
            id="checks_content",
        )
        return WindowSection(
            "checks",
            titled_header(
                "Checks",
                OpenFolderChip("checks"),
                help_button=WindowHelpChip("checks"),
            ),
            _checks_content,
            EmptyStatePanel(),
            id="screen_checks",
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
            Container: ``#screen_map`` holding a title label, a
            ``MemoryMapPanel`` (the ``#map_content`` coverage view) and an
            ``EmptyStatePanel``. Hidden at startup.

        Data Flow:
            - The ``MemoryMapPanel`` is driven by ``update_memory_map``,
              which reads the already-computed ``LoadedFile.ranges`` and
              ``LoadedFile.range_validity`` — no coverage is computed here
              (LLR-012.1 / LLR-012.4).
            - ``#map_content`` is a plain (non-scrolling) host: batch-93's
              inspector cockpit scrolls the region list inside its own pane
              (HLR-126) so the one-line stats strip always paints without
              scrolling (HLR-129) — the outer host must not swallow it below
              the fold (defect ④ of premise P-1).
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
        panel = MemoryMapPanel()
        # HLR-166 / LED .58 (a): the panel is the Map window's DECLARED
        # focus target — the empty-state/fallback landing (its only
        # focusable children are id-less region rows) — while the landing
        # after a load is the region row LLR-116.5 auto-selects. A
        # Container is not focusable by default — declare it here, at the
        # compose site, rather than in screens_directionb.py.
        # ``can_focus`` is a plain class attribute on Widget, so the
        # instance declaration shadows it for this panel only.
        panel.can_focus = True
        return WindowSection(
            "map",
            titled_header("Memory Map", help_button=WindowHelpChip("map")),
            Container(
                panel,
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
            Container: ``#screen_flow`` holding the header (title, ``?`` and
            the ``📂 Open flows/`` chip, batch-97 LLR-148.5) and the
            ``FlowBuilderPanel``. Hidden at startup.

        Data Flow:
            - Static composition. Activating the Flow rail item shows this
              container; Run posts ``FlowBuilderPanel.RunRequested``.

        Dependencies:
            Uses:
                - ``FlowBuilderPanel`` / ``OpenFolderChip``
            Used by:
                - ``compose``
        """
        return WindowSection(
            "flow",
            titled_header(
                "Flow Builder",
                OpenFolderChip("flows"),
                help_button=WindowHelpChip("flow"),
            ),
            self._compose_flow_builder_panel(),
            id="screen_flow",
            classes="db-screen hidden",
        )

    def _compose_flow_builder_panel(self) -> "FlowBuilderPanel":
        """The Flow Builder panel plus its Inc-7 context wiring.

        Summary:
            Installs the card-annotation context provider (E3 ruling 7):
            the panel pulls the CURRENT project/temp/loaded listing from
            the app at every repaint — the panel never lists directories
            itself (the pure textual classifier, E3 ruling 5, runs on the
            names the app hands it).

        Returns:
            FlowBuilderPanel: The composed panel.
        """
        panel = FlowBuilderPanel()
        panel.set_ref_context_provider(self._flow_ref_context)
        return panel

    def _compose_screen_flow_execution(self) -> Container:
        """Build the Flow Execution rail screen (``#screen_flow_execution``).

        Summary:
            The fx_A surface (batch-97 Inc-6, HLR-147; batch-94 Inc-003
            before it) — one :class:`FlowExecutionPanel` mounted between Flow
            Builder and Checks (the R-1 order). The panel is presentational:
            Import… / Run / Save Set / Load Set / Confirm post
            ``FlowExecutionPanel.*`` messages that the
            ``on_flow_execution_panel_*`` handlers route. A plain
            ``WindowSection`` (D10 amended): its header carries the
            ``📂 Open session`` chip and the window's ``?`` chip
            (LLR-148.5); ``c`` is the app's own binding, gated by
            ``check_action``.

        Returns:
            Container: ``#screen_flow_execution`` holding the header and the
            ``FlowExecutionPanel``. Hidden at startup.

        Dependencies:
            Uses:
                - ``FlowExecutionPanel`` / ``OpenFolderChip`` /
                  ``WindowHelpChip``
            Used by:
                - ``compose``
        """
        return WindowSection(
            "flow_execution",
            titled_header(
                "Flow Execution",
                OpenFolderChip("session"),
                help_button=WindowHelpChip("flow_execution"),
            ),
            FlowExecutionPanel(),
            id="screen_flow_execution",
            classes="db-screen hidden",
        )

    def _compose_screen_crc_designer(self) -> Container:
        """
        Summary:
            Build the rail-10 CRC Designer screen (``#screen_crc_designer``,
            HLR-V1 / LLR-V1.1) — the preview-only parameter-form surface hosting
            a :class:`CrcDesignerPanel`. Routed by the EXISTING data-driven
            ``action_show_screen`` (key ``0`` / rail click); no dedicated show
            handler is added.

        Args:
            None

        Returns:
            Container: ``#screen_crc_designer`` holding the header row
            (title + the ``📂 Open templates/`` chip, HLR-139) and the
            ``CrcDesignerPanel``. Hidden at startup.

        Data Flow:
            - Static composition. Activating the CRC Designer rail item shows
              this container; the panel owns its own form state and preset
              population (LLR-V1.2).

        Dependencies:
            Uses:
                - ``CrcDesignerPanel``
            Used by:
                - ``compose``
        """
        return WindowSection(
            "crc_designer",
            titled_header(
                "CRC Designer",
                OpenFolderChip("templates"),
                help_button=WindowHelpChip("crc_designer"),
            ),
            CrcDesignerPanel(),
            id="screen_crc_designer",
            classes="db-screen hidden",
        )

    def _compose_screen_split_join(self) -> WindowSection:
        """
        Summary:
            Build the Split / Join / Export screen (``#screen_split_join``,
            batch-95 change 4 / US-129, HLR-135) — the grafted terminal
            design (V1's cockpit chassis + V2's wide-regime band and the
            split-mode per-file gantt) as a ``WindowSection`` on the
            inc-003c seam: the title row carries title + ``?`` usage-help
            chip ONLY (HLR-139 contracts exactly four ``📂`` chips — this
            window gets none), and the focused-``?`` binding opens the
            authored ``split_join_export`` section. The window is
            palette-first with NO rail key (ruling Q6/7a): it mounts
            hidden beside the ten rail screens and opens from the ``^K``
            palette entry named "Split / Join / Export"
            (``action_open_split_join_export``); ``Esc`` closes it back to
            the rail screen it replaced.

        Args:
            None

        Returns:
            WindowSection: ``#screen_split_join`` (``classes="db-screen
            hidden"``) holding the whole graft chassis; the panel widget
            owns its plan/visor state and reads the loaded image/A2L live.

        Dependencies:
            Uses:
                - ``SplitJoinWindow`` / ``titled_header`` /
                  ``WindowHelpChip``
            Used by:
                - ``compose``
        """
        return SplitJoinWindow()

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
            Container: ``#screen_patch`` holding the header row (title + the
            ``📂 Open patches/`` chip, HLR-139) and a ``PatchEditorPanel``.
            Hidden at startup.

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
        return WindowSection(
            "patch",
            titled_header(
                "Patch Editor",
                OpenFolderChip("patch"),
                help_button=WindowHelpChip("patch"),
            ),
            PatchEditorPanel(),
            id="screen_patch",
            classes="db-screen hidden",
        )

    def _compose_screen_check_editor(self) -> WindowSection:
        """Build the Check Editor rail screen (``#screen_check_editor``).

        Summary:
            The batch-94 (US-003, HLR-001) check twin of the Patch Editor —
            one ``CheckEditorPanel`` (batch-97: the ledger + REPORT FIELDS
            card, HLR-145) mounted as its own rail surface between Patch
            Editor and A2B Diff (the R-1 order). Batch-97 (LLR-148.5, D9 /
            D10): a ``WindowSection`` whose ``titled_header`` carries the
            ``?`` help chip and the ``📂 Open checks/`` chip under the
            suffixed id ``#open_folder_checks_editor`` — the Checks screen
            already mounts ``#open_folder_checks`` (LLR-148.4).
            The panel is presentational: its controls emit
            ``CheckEditorPanel.ActionRequested`` messages that
            ``on_check_editor_panel_action_requested`` routes — the write
            assembles the ``kind="check"`` document and calls
            ``changes.io.write_change_document``; the validate rides
            ``changes.check.run_check_document``. No schema/model logic is
            built here (C-7).

        Returns:
            WindowSection: ``#screen_check_editor`` holding the header row
            (title, ``?``, ``📂 Open checks/``) and a ``CheckEditorPanel``.
            Hidden at startup.

        Dependencies:
            Uses:
                - ``CheckEditorPanel``
            Used by:
                - ``compose``
        """
        return WindowSection(
            "check_editor",
            titled_header(
                "Check Editor",
                OpenFolderChip("checks", id_suffix="editor"),
                help_button=WindowHelpChip("check_editor"),
            ),
            CheckEditorPanel(),
            id="screen_check_editor",
            classes="db-screen hidden",
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
            deps.Label("A2B Diff", classes="db-screen-title"),
            # batch-94 P4 fix (RC-2): the compose-time patches-folder listing
            # decides whether the panel composes its check-spec row at all —
            # the panel cannot scan for itself, and an empty listing must not
            # reserve the row's rows against the hex panes. The live listing
            # still rides ``set_check_files`` on every diff activation.
            AbDiffPanel(check_files=self._scan_spec_files()),
            id="screen_diff",
            classes="db-screen hidden",
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
            - The widget ids are kept as the A2L renderers' mount targets: the
              tags pane keeps ``#a2l_tags_list``, ``#a2l_tags_summary``, the
              filter row inputs/buttons, the ``#a2l_filter_menu`` overlay and
              its list; the hex pane keeps ``#alt_hex_view`` /
              ``#alt_hex_scroll`` / ``#alt_search_input`` / ``#alt_goto_input``
              and the find/goto buttons.

        Dependencies:
            Used by:
                - ``compose``

        US-038 polish (LLR-042.2): the tags pane carries the queryable
        ``density-compact`` class (tightened pane padding, mirroring the
        ``#workspace_body.density-compact`` precedent). The tag table is an
        ``A2LTagTable`` with ``cell_padding=1`` (at least one blank column
        between adjacent cells, R-TUI-042a.2) and ``fixed_columns=2`` (the
        Address and Length columns stay at their own x under a horizontal
        scroll while the other columns scroll under them, R-TUI-042a.4); the
        fixed column header is the Textual ``DataTable`` default
        (LLR-042.1, verify-not-build). Tag enrichment, paging and per-row
        severity colouring layer on the same widget ids.
        """
        _tags_pane = Container(
            deps.Label("A2L Tags", id="a2l_tags_title"),
            Container(
                OsClipboardInput(placeholder="Filter tags", id="a2l_tags_filter_input"),
                Button("Field: name", id="a2l_filter_field"),
                Button("All", id="a2l_filter_all"),
                Button("Invalid", id="a2l_filter_invalid"),
                Button("In-Memory", id="a2l_filter_inmem"),
                OsClipboardInput(
                    placeholder="Find in tag table", id="a2l_tag_find_input"
                ),
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
            A2LTagTable(
                id="a2l_tags_list",
                zebra_stripes=True,
                cursor_type="row",
                cell_padding=1,
                fixed_columns=2,
            ),
            deps.Label("", id="a2l_tags_summary"),
            id="a2l_tags_pane",
            classes="db-pane density-compact",
        )
        _hex_pane = Container(
            A2LDetailCard(
                id="a2l_detail_card",
                markup=False,
                wrap=True,
                min_width=1,
                auto_scroll=False,
            ),
            deps.Label("Hex Viewer", id="alt_hex_title"),
            Container(
                OsClipboardInput(
                    placeholder="Search ASCII text", id="alt_search_input"
                ),
                Button("Find Next", id="alt_search_button"),
                OsClipboardInput(placeholder="Goto 0xADDR", id="alt_goto_input"),
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
        # The change-3 header row (title + the `?` usage-help chip, HLR-140)
        # leads the screen like every other window; `#a2l_panes` holds the
        # `1fr` remainder (its height rule in styles.tcss).
        return WindowSection(
            "a2l",
            titled_header("A2L Explorer", help_button=WindowHelpChip("a2l")),
            _panes,
            id="screen_a2l",
            classes="db-screen hidden",
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
            deps.Label("MAC File Content", id="mac_title"),
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
                _CopyRowTable(
                    id="mac_records_list", zebra_stripes=True, cursor_type="row"
                ),
                deps.Label("", id="mac_records_summary"),
                id="mac_scroll",
            ),
            id="mac_records_pane",
            classes="db-pane",
        )
        _hex_pane = Container(
            deps.Label("Hex Viewer", id="mac_hex_title"),
            Container(
                OsClipboardInput(
                    placeholder="Search ASCII text", id="mac_search_input"
                ),
                Button("Find Next", id="mac_search_button"),
                OsClipboardInput(placeholder="Goto 0xADDR", id="mac_goto_input"),
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
                    "Address",
                    "Length",
                    "Tag",
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
