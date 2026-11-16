"""s19_app.tui.app.reports — S19TuiApp mixin: reports (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence
from textual import work
from ..changes.io import list_change_documents
from ..models import ProjectVariantSet
from ..screens import ReportViewerScreen
from ..screens_directionb import AbDiffPanel, CheckEditorPanel, PatchEditorPanel
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
    list_project_reports,
)
from ..services.project_gather_service import (
    PROJECT_CHECKS_DIR,
    PROJECT_PATCHES_DIR,
    scoped_home,
    scoped_home_target,
)
from ..services.variant_execution_service import (
    SCOPE_ACTIVE,
    VariantExecutionResult,
    execute_project_variants,
)
from ..workspace import _path_traverses_reparse_point, WORKAREA_PATCHES
from . import deps
from .shared import (DOCUMENT_OK, RecordedDocumentState)


REPORT_FILTERS_DIR_NAME = "filters"
"""Project subdirectory scanned for report-filter files (batch-35 US-056,
LLR-056.1): ``<project_dir>/filters/*.json`` feeds the report-viewer
dropdown. Net-new name — no prior production use (probe 2026-07-10)."""


def format_report_log_line(
    kind: str,
    source: str,
    output: str,
    outcome: str,
) -> str:
    """
    Summary:
        Build the single-line, metadata-only log record for a
        report-generation event (N3 observability). The line names the
        report KIND, its SOURCE artifact(s), the OUTPUT path(s) and the
        OUTCOME — and never carries report body content or memory/byte
        values, honoring the emitter modules' deliberate "no body in logs"
        design (spec AC-5).

    Args:
        kind (str): Report kind — ``"project"`` / ``"before-after"`` /
            ``"diff"``.
        source (str): Source artifact name(s)/path(s) — metadata only.
        output (str): Written output path(s), or ``"-"`` when none was
            written (a refusal/failure).
        outcome (str): ``"ok"`` on success, else a short reason string
            (e.g. ``"rejected: ..."`` / ``"refused"`` / ``"failed: ..."``)
            that carries NO body content.

    Returns:
        str: e.g.
        ``"report kind=before-after source=prg.s19 output=a.md|a.html outcome=ok"``.

    Data Flow:
        - Pure string builder; the caller logs it on the ``"s19tui"``
          logger (``self.logger``) so it reaches
          ``.s19tool/logs/s19tui.log`` (AC-6).

    Dependencies:
        Uses:
            - none
        Used by:
            - ``S19TuiApp._log_report_event``

    Example:
        >>> format_report_log_line("diff", "a.s19|b.s19", "d.md|d.html", "ok")
        'report kind=diff source=a.s19|b.s19 output=d.md|d.html outcome=ok'
    """
    return f"report kind={kind} source={source} output={output} outcome={outcome}"


class ReportsMixin:

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
            - Gather ``LoadedFile.path``, the active project dir and the
              display name **on the UI thread** (reading ``current_file`` from
              a worker would race a concurrent load), then hand them to
              :meth:`_start_before_after_worker`. The composer validates the
              five LLR-038.2 preconditions and every LLR-038.4 refusal class
              itself — this handler never pre-duplicates them.
            - **N5 (batch-68): the composition itself no longer runs here.**
              It used to, on the UI event loop, so the terminal stopped
              repainting for its whole duration. This method now only
              validates, sets the progress kickoff, and dispatches; the
              ``written`` / refusal status lines are written by the worker.

        Dependencies:
            Uses:
                - ``_start_before_after_worker`` (the composer's new home)
                - ``read_report_filter_text`` / ``parse_report_filter``
                - ``resolve_report_filter`` / ``_compute_a2l_enriched_tags``
                - ``_active_project_dir`` / ``set_status`` / ``set_progress``
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
        # N5 (batch-68): the composer is the expensive step and used to run
        # HERE, on the UI event loop — the terminal stopped repainting for its
        # whole duration, so a slow report was indistinguishable from a hang.
        # Validation above stays on the UI thread (it is cheap and it owns the
        # early-return status writes); only the composition is dispatched.
        # F-10: the active-project dir is resolved BEFORE the begin, so nothing
        # that can raise sits between the begin and the dispatch.
        project_dir = self._active_project_dir()
        # R-BEFORE-AFTER-REPORT-001.24/.35: the A2L and MAC the session holds,
        # gathered on the UI thread (a worker reading them would race a load).
        # "No MAC loaded" is mac_path None, never an empty list (R-CMP-003.2).
        report_a2l_data = self.current_a2l_data
        report_a2l_records = self._compute_a2l_enriched_tags() or None
        report_mac_records = (
            loaded.mac_records
            if loaded is not None and loaded.mac_path is not None
            else None
        )
        gen = self._busy_begin_action("before_after")
        self._start_before_after_worker(
            loaded.path if loaded is not None else None,
            project_dir,
            report_filter,
            loaded.path.name if loaded is not None else "-",
            gen=gen,
            a2l_data=report_a2l_data,
            a2l_records=report_a2l_records,
            mac_records=report_mac_records,
        )

    @work(thread=True, exclusive=True, group="before_after_report")
    def _start_before_after_worker(
        self,
        loaded_path: Optional[Path],
        project_dir: Optional[Path],
        report_filter: Optional[ReportFilterMatcher],
        source_name: str,
        *,
        gen: int,
        a2l_data: Optional[dict] = None,
        a2l_records: Optional[Sequence[dict]] = None,
        mac_records: Optional[Sequence[dict]] = None,
    ) -> None:
        """
        Summary:
            Off-thread before/after report composition (N5, batch-68). Calls
            the LLR-038.2 composer and marshals every UI write back through
            ``call_from_thread``; ``_log_report_event`` is called directly
            because it touches only ``self.logger``, never a widget — the same
            division the shipped ``_start_generate_report_worker`` uses.

            The progress bar is driven at three seams and is NEVER left
            mid-fill: the caller sets 15 before dispatch, this worker sets 100
            on success and 0 on both the refusal and the crash arm.

        Args:
            loaded_path (Optional[Path]): The loaded image path, or ``None``.
            project_dir (Optional[Path]): Active project dir for the composer.
            report_filter (Optional[ReportFilterMatcher]): Resolved filter, or
                ``None`` when no filter file is configured.
            source_name (str): Display name for the log line — resolved on the
                UI thread by the caller, because reading ``self.current_file``
                from a worker would race a concurrent load.
            gen (int): The busy run's generation from ``_busy_begin_action``
                (keyword-only; Inc 12a S-m), passed to every ``end_busy``.
            a2l_data (Optional[dict]): The loaded A2L payload, or ``None``
                (gathered on the UI thread by the caller).
            a2l_records (Optional[Sequence[dict]]): The A2L enriched tags, or
                ``None`` when there are none.
            mac_records (Optional[Sequence[dict]]): The loaded MAC records, or
                ``None`` when no MAC file is loaded.

        Returns:
            None: Effects only — the written report pair, a log line, the
            status text and the progress bar.

        Data Flow:
            - Consumes ``ChangeService.last_summary``; produces the written
              ``.md``/``.html`` pair and the status/progress surface.

        Dependencies:
            Uses:
                - ``compose_before_after_report`` / ``_log_report_event``
                - ``set_status`` / ``set_progress`` (via ``call_from_thread``)
            Used by:
                - ``action_before_after_report`` (key binding ``b``)
        """
        try:
            try:
                result = deps.compose_before_after_report(
                    self._change_service.last_summary,
                    loaded_path,
                    project_dir=project_dir,
                    workarea=self.workarea,
                    report_filter=report_filter,
                    a2l_data=a2l_data,
                    a2l_records=a2l_records,
                    mac_records=mac_records,
                )
            except Exception as exc:
                self.logger.exception("Before/after report failed: %s", exc)
                self._log_report_event(
                    "before-after",
                    source_name,
                    "-",
                    f"failed: {type(exc).__name__}",
                    ok=False,
                )
                self.call_from_thread(
                    self.end_busy,
                    "before_after",
                    gen,
                    f"Before/after report failed: {type(exc).__name__}: {exc}",
                )
                return
            if result.written:
                self._log_report_event(
                    "before-after",
                    source_name,
                    f"{result.md_path}|{result.html_path}",
                    "ok",
                    ok=True,
                )
                self.call_from_thread(
                    self.end_busy,
                    "before_after",
                    gen,
                    f"Before/after report written: {result.md_path} "
                    f"| {result.html_path}",
                )
                return
            self._log_report_event(
                "before-after", source_name, "-", "refused", ok=False
            )
            # Refused is a legitimate outcome, not a crash — but the bar
            # must still come back down rather than sit at the kickoff value.
            self.call_from_thread(
                self.end_busy,
                "before_after",
                gen,
                "Before/after report refused: " + " ".join(result.diagnostics),
            )
        except BaseException:
            self.call_from_thread(self._busy_fail, "before_after", gen)
            raise

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
        resolved = deps.resolve_input_path(Path(raw), self.base_dir)
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
        # CR12b-3: a running project load or Save owns the session's regions.
        if self._running_session_action() is None:
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
            if not fallback_batch and deps.read_project_manifest(project_dir) is None:
                self.set_status(
                    "Report: no manifest and no loaded change/check file - "
                    "nothing to report."
                )
                return
            self.set_status("Report: no prior execution - running active scope...")
        else:
            self.set_status("Report: generating from last execution...")
        # N5: drive the persistent #progress_bar so report generation shows
        # visible activity (the worker is off-thread and otherwise silent on the
        # bar). Kickoff → in-progress; worker mid → 55; success → 100; failure → 0.
        gen = self._busy_begin_action("report")
        self._start_generate_report_worker(
            project_dir,
            variant_set,
            context_bytes,
            last,
            fallback_batch,
            tuple(declared_regions),
            report_filter,
            gen=gen,
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
        *,
        gen: int,
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
            gen (int): The busy run's generation from ``_busy_begin_action``
                (keyword-only; Inc 12a S-m), passed to ``step_busy`` and the end.

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
        def report_failed(exc: BaseException) -> None:
            """LLR-110.2 — the SINGLE tool-failure branch, shared by both sites.

            Both ``except`` handlers below call this rather than repeating the
            log/progress/status sequence. Duplicating it is how the two branches
            drift apart: one gets a progress reset and the other does not, and
            nothing catches it because each is exercised by a different test.
            ``TC-572`` asserts the sequence exists exactly once.
            """
            self.logger.exception("Report generation failed: %s", exc)
            self._log_report_event(
                "project",
                project_dir.name,
                "-",
                f"failed: {type(exc).__name__}",
                ok=False,
            )
            # N5: reset the bar on a crashed report — never leave it mid-fill.
            self.call_from_thread(
                self.end_busy,
                "report",
                gen,
                f"Report failed: {type(exc).__name__}: {exc}",
            )

        try:
            try:
                if last is None:
                    scope = SCOPE_ACTIVE
                    assignment_source = (
                        REPORT_SOURCE_MANIFEST
                        if deps.read_project_manifest(project_dir) is not None
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
            except ValueError as exc:
                self._log_report_event(
                    "project", project_dir.name, "-", f"rejected: {exc}", ok=False
                )
                # N5: reset the bar on a rejected report — never leave it
                # mid-fill.
                self.call_from_thread(
                    self.end_busy, "report", gen, f"Report rejected: {exc}"
                )
                return
            except Exception as exc:
                report_failed(exc)
                return
            # LLR-110.1 — generation sits OUTSIDE the operator-input span.
            #
            # It used to sit INSIDE the block above, so a ``ValueError`` raised
            # anywhere in the generator — an internal accounting slip, a formatter
            # that could not render a value — surfaced to the operator as
            # "Report rejected: ...", i.e. as though THEY had typed something
            # invalid. The operator-input span is the options construction and the
            # scope guard; those are the only places a ``ValueError`` legitimately
            # means "your input was out of domain" (P-11). Everything the tool does
            # after that is the tool's own failure and is attributed to the tool.
            #
            # This re-routes by CALL SITE, not by cause (non-claim (g)): a
            # ``ValueError`` is not intrinsically an operator error, so no analysis
            # of the exception could have made this decision — only its position.
            #
            # N5: mid-progress before the heavy assembly (thread-safe via
            # call_from_thread — step_busy touches the UI widget).
            self.call_from_thread(self.step_busy, "report", gen, 2)
            try:
                report_path = deps.generate_project_report(
                    project_dir, results, options, variant_set=variant_set
                )
            except Exception as exc:
                report_failed(exc)
                return
            self._log_report_event(
                "project", project_dir.name, str(report_path), "ok", ok=True
            )
            self.call_from_thread(self._finish_generate_report, report_path, gen)
        except BaseException:
            self.call_from_thread(self._busy_fail, "report", gen)
            raise

    def _log_report_event(
        self,
        kind: str,
        source: str,
        output: str,
        outcome: str,
        *,
        ok: bool,
    ) -> None:
        """
        Summary:
            Emit one metadata-only report-generation log line on the app's
            ``"s19tui"`` file logger (N3 observability): INFO on success,
            WARNING on failure/refusal — so no report action is ever silent
            in ``.s19tool/logs/s19tui.log`` (spec AC-1..4/AC-6). The line
            carries only metadata (kind, source, output path, outcome),
            never report body content (AC-5).

        Args:
            kind (str): Report kind — ``"project"`` / ``"before-after"`` /
                ``"diff"``.
            source (str): Source artifact name(s)/path(s) — metadata only.
            output (str): Written output path(s), or ``"-"`` on
                refusal/failure.
            outcome (str): ``"ok"`` or a short reason string (no body).
            ok (bool): ``True`` logs at INFO; ``False`` at WARNING.

        Returns:
            None

        Data Flow:
            - Builds the line via :func:`format_report_log_line` and routes
              it to ``self.logger`` (the ``setup_logging`` rotating file
              logger). Thread-safe — callable from the generation worker.

        Dependencies:
            Uses:
                - :func:`format_report_log_line` / ``self.logger``
            Used by:
                - ``_start_generate_report_worker`` (project)
                - ``action_before_after_report`` (before-after)
                - ``on_ab_diff_panel_report_requested`` (diff)
        """
        line = format_report_log_line(kind, source, output, outcome)
        if ok:
            self.logger.info(line)
        else:
            self.logger.warning(line)

    def _finish_generate_report(self, report_path: Path, gen: int) -> None:
        """
        Summary:
            UI-thread close of a successful generation: DROP the retained
            execution results (and their mem_maps — the E7 risk item),
            then show the written report's project-relative path in the
            status line (LLR-008.5; project-relative because the status
            log trims lines to 50 characters).

        Args:
            report_path (Path): The written report file.
            gen (int): The ``report`` run's generation (Inc 12a S-m).

        Returns:
            None

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``_start_generate_report_worker`` (via ``call_from_thread``)
        """
        self._last_execution = None
        self.end_busy(
            "report", gen, f"Report: {report_path.parent.name}/{report_path.name}"
        )

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

    def _change_doc_save_home(self) -> Optional[Path]:
        """
        Summary:
            Resolve the change-1 (HLR-138) scoped home for a NEW change/check
            document save: with an active project, the per-artifact project
            folder — ``<project>/patches/`` for a change-set,
            ``<project>/checks/`` for a check document (the wire ``kind``
            discriminator) — so project artifacts live in organized project
            folders; with NO project, ``None``, and the writer keeps the
            COMMON ``workarea/patches/`` home. Both limbs ride
            ``project_gather_service.scoped_home``'s containment check, so
            the scoped homes obey the same ``.s19tool/workarea/`` law as the
            gather.

        Args:
            None

        Returns:
            Optional[Path]: The scoped save destination, or ``None`` without
            a project (the writer's COMMON-home default). A containment
            refusal propagates as ``WorkareaContainmentError`` — the save
            action surfaces it through the service result, never a crash.

        Data Flow:
            - ``_active_project_dir()`` → ``None`` ⇒ ``None``.
            - Else ``scoped_home(project_dir, <kind home>,
              common=workarea/patches)``.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``scoped_home``
                - ``_change_service.document.kind`` (the discriminator)
            Used by:
                - ``on_patch_editor_panel_action_requested`` (save_doc)
        """
        project_dir = self._active_project_dir()
        if project_dir is None:
            return None
        kind = self._change_service.document.kind
        subdir = PROJECT_CHECKS_DIR if kind == "check" else PROJECT_PATCHES_DIR
        return scoped_home(project_dir, subdir, self.workarea / WORKAREA_PATCHES)

    def _check_home(self) -> Path:
        """Resolve the check home path without creating anything (Inc 6).

        Summary:
            The one Check-Editor Write destination (R-CHKED-031): with a
            project ``<project>/checks/``, without one the COMMON
            ``workarea/patches/`` library. Path arithmetic only — Write's
            placement creates and containment-checks the folder, so this
            must never mkdir (the open-folder chips' missing-folder state
            stays observable).

        Args:
            None

        Returns:
            Path: ``scoped_home_target(_active_project_dir(),
            PROJECT_CHECKS_DIR, workarea/patches)``.

        Data Flow:
            - ``scoped_home_target`` — pure path arithmetic, no IO.

        Dependencies:
            Uses:
                - ``scoped_home_target`` / ``_active_project_dir``
            Used by:
                - ``on_check_editor_panel_action_requested`` (Write)
                - ``_spec_homes`` (the ``checks/`` home in a project)
        """
        return scoped_home_target(
            self._active_project_dir(),
            PROJECT_CHECKS_DIR,
            self.workarea / WORKAREA_PATCHES,
        )

    def _change_homes(self) -> list[tuple[str, Path]]:
        """The change-list folders with their name prefixes (Inc 6, I-6).

        Summary:
            Without a project one home — the COMMON ``workarea/patches/``,
            listed bare. With a project the project's ``checks/`` then
            ``patches/`` (each prefixed with its folder name) then the
            COMMON library as ``library/`` (revised D-3). The order of the
            list is the order of the listing — project entries first, then
            the library — never one global sort.

        Args:
            None

        Returns:
            list[tuple[str, Path]]: ``(prefix, folder)`` pairs; nothing is
            created.

        Data Flow:
            - ``_active_project_dir()`` chooses the shape; path arithmetic
              only.

        Dependencies:
            Uses:
                - ``_active_project_dir``
            Used by:
                - ``_scan_patch_change_files`` / ``_resolve_listed_file``
                  (via ``on_patch_editor_panel_change_file_selected``)
        """
        project_dir = self._active_project_dir()
        if project_dir is None:
            return [("", self.workarea / WORKAREA_PATCHES)]
        return [
            ("checks/", project_dir / PROJECT_CHECKS_DIR),
            ("patches/", project_dir / PROJECT_PATCHES_DIR),
            ("library/", self.workarea / WORKAREA_PATCHES),
        ]

    def _spec_homes(self) -> list[tuple[str, Path]]:
        """The spec-list folders with their name prefixes (Inc 6, I-6).

        Summary:
            The check-spec listing's homes (revised D-3): without a project
            the COMMON ``workarea/patches/`` listed bare; with a project the
            check home as ``checks/`` then the COMMON library as
            ``library/``. A spec list keeps its canon source (the check
            home), so it shows no ``patches/``.

        Args:
            None

        Returns:
            list[tuple[str, Path]]: ``(prefix, folder)`` pairs; nothing is
            created.

        Data Flow:
            - ``_active_project_dir()`` chooses the shape; the project's
              ``checks/`` home rides ``_check_home()``.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``_check_home``
            Used by:
                - ``_scan_spec_files`` / ``_resolve_listed_file``
                  (via the Check Editor and A2B Diff pick guards)
                - ``on_check_editor_panel_action_requested`` (the Write
                  status names the home prefix, R-CHKED-032)
        """
        project_dir = self._active_project_dir()
        if project_dir is None:
            return [("", self.workarea / WORKAREA_PATCHES)]
        return [
            ("checks/", self._check_home()),
            ("library/", self.workarea / WORKAREA_PATCHES),
        ]

    def _scan_patch_change_files(self) -> List[str]:
        """Discover the change list for the Patch Editor dropdown (Inc 6).

        Summary:
            Return every ``*.json`` change file of each change home, in home
            order (project entries, then the COMMON library), each prefixed
            with its folder name in a project (revised D-3). Each home's
            names are SORTED deterministically (F-Q2), and the read-path
            security fold holds at discovery time (F1): a symlink entry is
            SKIPPED (never listed). The homes' lists are JOINED in home
            order — not one global sort, since ``library/`` would sort
            between ``checks/`` and ``patches/``.

        Args:
            None

        Returns:
            List[str]: The prefixed file names (bare without a project); an
            empty list when every home is absent or holds no change file.

        Data Flow:
            - For each ``(prefix, folder)`` of ``_change_homes()``, append
              ``prefix + name`` for every ``list_change_documents(folder)``
              name (sorted, links skipped by the helper), joined in home
              order.

        Dependencies:
            Uses:
                - ``_change_homes`` / ``list_change_documents``
            Used by:
                - ``_prefill_patch_change_files``

        Example:
            >>> app._scan_patch_change_files()
            ['changes-1.json', 'changes.json']
        """
        # Inc 6 (revised D-3): the change list spans the project homes and
        # the COMMON library, joined in home order.
        names: list[str] = []
        for prefix, folder in self._change_homes():
            for name, _is_check in list_change_documents(folder):
                names.append(prefix + name)
        return names

    def _scan_spec_files(self) -> List[str]:
        """Discover the spec list for the two spec dropdowns (Inc 6).

        Summary:
            As :meth:`_scan_patch_change_files`, over ``_spec_homes()``: the
            check home (prefixed ``checks/`` in a project) then the COMMON
            library (``library/``), joined in home order; bare names without
            a project. The Check Editor Spec dropdown and the A2B Diff
            check-spec list both read it (revised D-3).

        Args:
            None

        Returns:
            List[str]: The prefixed spec file names; empty when every home
            is absent or empty.

        Data Flow:
            - For each ``(prefix, folder)`` of ``_spec_homes()``, append
              ``prefix + name`` per ``list_change_documents(folder)`` name.

        Dependencies:
            Uses:
                - ``_spec_homes`` / ``list_change_documents``
            Used by:
                - ``_prefill_check_editor`` / ``_prefill_diff_check_files`` /
                  ``_compose_screen_diff`` / ``_refill_document_lists``
        """
        names: list[str] = []
        for prefix, folder in self._spec_homes():
            for name, _is_check in list_change_documents(folder):
                names.append(prefix + name)
        return names

    def _resolve_listed_file(
        self, value: str, homes: list[tuple[str, Path]]
    ) -> Optional[Path]:
        """Resolve one listed pick against its homes with the pick guard (Inc 6).

        Summary:
            The one pick guard shared by the Patch Editor change-file pick,
            the Check Editor spec pick and the A2B Diff check-spec pick
            (R-PATCH-DOC-DROPDOWN-001.3/.4, R-CHKED-044, R-DIFF-CHK.5). Pick
            the home whose prefix starts ``value`` (the empty prefix matches
            only when it is the sole home); ``name = value[len(prefix):]``;
            ``path = folder / name`` (UNRESOLVED). Refuse — return ``None``
            — when no home matches, the name is empty, holds a separator or
            is ``.`` or ``..``, the walk from the work area down to the file
            meets a link/reparse point (the Write guard's walk and stop point, S-3),
            or the resolved path is not inside the resolved work area. Else
            return the unresolved ``path`` (S-4: the Save project classifier
            compares unresolved text).

        Args:
            value (str): The listed value (``checks/<n>``, ``patches/<n>``,
                ``library/<n>`` or a bare name).
            homes (list[tuple[str, Path]]): The ``(prefix, folder)`` list of
                the pick's listing.

        Returns:
            Optional[Path]: The unresolved ``folder / name``, or ``None`` on
            any refusal.

        Data Flow:
            - Prefix match → name extraction → textual-shape checks →
              ``_path_traverses_reparse_point(path,
              stop_at=self.workarea.parent)`` or ``_is_reparse_point(
              self.workarea.parent)`` → ``path.resolve()`` inside
              ``self.workarea.resolve()``.

        Dependencies:
            Uses:
                - ``workspace._path_traverses_reparse_point`` /
                  ``_is_reparse_point`` / ``Path.resolve``
            Used by:
                - ``on_patch_editor_panel_change_file_selected``
                - ``on_check_editor_panel_spec_file_selected``
                - ``on_ab_diff_panel_check_file_selected``
        """
        folder: Optional[Path] = None
        prefix_len = 0
        for prefix, candidate_folder in homes:
            if prefix == "":
                # The bare (no-project) home matches only when it is the
                # sole home; in a project a bare name matches no prefix and
                # is refused.
                if len(homes) == 1:
                    folder = candidate_folder
                    prefix_len = 0
                break
            if value.startswith(prefix):
                folder = candidate_folder
                prefix_len = len(prefix)
                break
        if folder is None:
            return None
        name = value[prefix_len:]
        if (
            name in ("", ".", "..")
            or "/" in name
            or "\\" in name
        ):
            return None
        path = folder / name
        if (
            _path_traverses_reparse_point(path, stop_at=self.workarea.parent)
            or deps._is_reparse_point(self.workarea.parent)
        ):
            return None
        try:
            resolved = path.resolve()
            root = self.workarea.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(root):
            return None
        return path

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

    def _refill_document_lists(self) -> None:
        """Refill the three document lists after a project change (Inc 6, E3A-04).

        Summary:
            Re-scan the change list and the spec list once
            ``current_project_dir`` holds the new project, so the Patch
            Editor File dropdown, the Check Editor Spec dropdown and the A2B
            Diff check-spec list all show the new project's homes plus the
            COMMON library (revised D-3). Called from the project install and
            every committed Save project (plain, create, save-as) — never
            from ``_reset_project_session``, which runs before the
            assignment.

        Args:
            None

        Returns:
            None

        Data Flow:
            - ``_prefill_patch_change_files()``; the Check Editor panel when
              mounted gets ``set_spec_files(self._scan_spec_files())`` (the
              Spec half only — the A2L picker half stays on screen entry);
              ``_prefill_diff_check_files()``. Each tolerates an unmounted
              panel.

        Dependencies:
            Uses:
                - ``_prefill_patch_change_files`` / ``_scan_spec_files`` /
                  ``_prefill_diff_check_files``
            Used by:
                - ``_install_prepared_project`` / ``_on_project_saved``
        """
        self._prefill_patch_change_files()
        try:
            panel = self.query_one("#check_editor_panel", CheckEditorPanel)
        except Exception:
            panel = None
        if panel is not None:
            panel.set_spec_files(self._scan_spec_files())
        self._prefill_diff_check_files()

    @work(thread=True, exclusive=True, group="diff_report")
    def _start_diff_report_worker(
        self,
        panel: AbDiffPanel,
        result: object,
        kwargs: dict,
        diff_source: str,
        *,
        gen: int,
    ) -> None:
        """
        Summary:
            Off-thread A2B diff report generation (N5, batch-68). Runs the
            markdown generator, then the HTML generator, marshalling every
            ``panel.set_status`` and ``set_progress`` write back to the UI
            thread; ``_log_report_event`` is called directly because it only
            touches ``self.logger``.

            Progress is driven at four seams and never left mid-fill: the
            caller sets 15, this worker sets 55 between the two generators,
            100 on full success, and 0 on **each** of the three failure arms —
            markdown refused, HTML refused (markdown already written), and an
            unexpected crash.

        Args:
            panel (AbDiffPanel): The live panel, resolved on the UI thread by
                the caller; every method call on it is marshalled.
            result (object): The retained ``_diff_last_result`` comparison.
            kwargs (dict): The shared generator arguments assembled on the UI
                thread (mem maps, destination, A2L/MAC records).
            diff_source (str): Display name for the log line.
            gen (int): The busy run's generation from ``_busy_begin_action``
                (keyword-only; Inc 12a S-m), passed to ``step_busy`` and the end.

        Returns:
            None: Effects only — the written pair, a log line, the panel status
            and the progress bar.

        Data Flow:
            - Consumes the retained diff result; produces the ``.md``/``.html``
              pair and the panel status surface.

        Dependencies:
            Uses:
                - ``generate_diff_report`` / ``generate_diff_report_html``
                - ``_log_report_event`` / ``AbDiffPanel.set_status``
            Used by:
                - ``on_ab_diff_panel_report_requested``
        """
        # R-CMP-005.17: set only after the Markdown file is written, so a
        # Markdown refusal or exception removes nothing.
        md_written_path: Optional[Path] = None

        def _drop_orphan_md() -> None:
            if md_written_path is None:
                return
            try:
                md_written_path.unlink(missing_ok=True)
            except OSError as exc:
                self.logger.warning(
                    "report kind=diff orphan not removed: %s", type(exc).__name__
                )

        try:
            try:
                md = deps.generate_diff_report(result, **kwargs)
                if not md.written:
                    text = "Report refused: " + "; ".join(md.diagnostics)
                    self._log_report_event(
                        "diff", diff_source, "-", "refused", ok=False
                    )
                    self.call_from_thread(
                        self.end_busy, "diff_report", gen, text
                    )
                    self.call_from_thread(panel.set_status, text, "sev-error")
                    return
                md_written_path = md.path
                self.call_from_thread(self.step_busy, "diff_report", gen, 2)
                html = deps.generate_diff_report_html(result, **kwargs)
            except Exception as exc:
                self.logger.exception("Diff report failed: %s", exc)
                _drop_orphan_md()
                self._log_report_event(
                    "diff", diff_source, "-", f"failed: {type(exc).__name__}",
                    ok=False,
                )
                text = f"Diff report failed: {type(exc).__name__}: {exc}"
                self.call_from_thread(self.end_busy, "diff_report", gen, text)
                self.call_from_thread(panel.set_status, text, "sev-error")
                return
            if not html.written:
                _drop_orphan_md()
                text = "HTML report refused: " + "; ".join(html.diagnostics)
                self._log_report_event(
                    "diff", diff_source, "-", "refused (html)", ok=False
                )
                self.call_from_thread(self.end_busy, "diff_report", gen, text)
                self.call_from_thread(panel.set_status, text, "sev-error")
                return
            self._log_report_event(
                "diff", diff_source, f"{md.path}|{html.path}", "ok", ok=True
            )
            text = f"Diff report written: {md.path}  |  {html.path}"
            self.call_from_thread(self.end_busy, "diff_report", gen, text)
            self.call_from_thread(panel.set_status, text, "sev-ok")
        except BaseException:
            self.call_from_thread(self._busy_fail, "diff_report", gen)
            raise

    def _reopen_active_document(self, state: Optional[RecordedDocumentState]) -> None:
        """Main-thread install half of the recorded-document reopen (LLR-170.3).

        Summary:
            ``state`` was built on the worker (``_prepare_project_load``);
            here a ``DOCUMENT_OK`` state goes into the fresh change service
            (its ``source_path`` already set), the panel is marked loaded
            and re-rendered. The read, the problem and the warning moved to
            the worker step (E1 A7).

        Args:
            state (Optional[RecordedDocumentState]): The worker's reopen
                result, or ``None`` when nothing is recorded.

        Returns:
            None

        Dependencies:
            Uses: PatchEditorPanel.mark_loaded / _patch_editor_load_tail
            Used by: _install_prepared_project (step 5)
        """
        if state is None or state.outcome != DOCUMENT_OK:
            return
        self._change_service.document = state.document
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            # Not mounted (headless unit tests): the service holds the
            # document either way, as in the project reset.
            return
        panel.mark_loaded()
        self._patch_editor_load_tail(panel)
