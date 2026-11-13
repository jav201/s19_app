"""s19_app.tui.app.project_load — S19TuiApp mixin: project_load (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from pathlib import Path, PureWindowsPath
import stat
import time
from typing import Any, Callable, Literal, Optional, Sequence, Tuple
from textual import work
from textual.widgets import TextArea
from ...utils import safe_text
from ..models import LoadedFile, ProjectVariantSet, VariantDescriptor
from ..screens import (
    ConfirmQuestionScreen,
    LOAD_RESULT_SELECT_VARIANT,
    LoadChoice,
    LoadDialog,
    LoadResultScreen,
)
from ..flow_screens import FlowBuilderPanel
from ..screens_directionb import PatchEditorPanel
from ..services.change_service import ChangeService
from ..services.project_gather_service import painted_names
from ..services.variant_execution_service import (
    DOCUMENT_REASON_IO_ERROR,
    DOCUMENT_REASON_LINK,
    DOCUMENT_REASON_TOO_LARGE,
    DOCUMENT_REASON_UNREADABLE,
    PROBLEM_NOT_READABLE,
    PROJECT_MANIFEST_NAME,
    STEP_CHECK_THEN_LOAD,
    STEP_OPEN_FROM_EDITOR,
    STEP_REPLACE_A2L,
    ProjectFileProblem,
    ProjectManifest,
    document_problem_file,
    manifest_is_damaged,
)
from ..workspace import (
    MAC_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    WORKAREA_TEMP,
    build_variant_set,
    list_workarea_files,
    RECENT_PROBLEM_TOO_LARGE,
    RECENT_PROBLEM_UNREADABLE,
    read_recent_sources,
    recent_kind,
)
from . import deps
from .shared import (
    _TYPED_REFUSAL_TOKENS,
    A2LCacheEntry,
    PreparedLoad,
    DOCUMENT_OK,
    DOCUMENT_MISSING,
    DOCUMENT_LINK,
    DOCUMENT_TOO_LARGE,
    DOCUMENT_UNREADABLE,
    DOCUMENT_IO_ERROR,
    RecordedDocumentState,
)


#: Inc 9b (Q5): the next-step token painted after a recent-sources store
#: problem word in the Load dialog's recents section (LLR-173.4g).
_RECENT_PROBLEM_STEPS: dict[str, str] = {
    RECENT_PROBLEM_TOO_LARGE: "the next load starts a new list",
    RECENT_PROBLEM_UNREADABLE: "check that the recent-sources file can be opened",
}

#: Inc 10 (LLR-174.4): the three question kinds the load seam takes; the
#: literal set is closed and checked by an AST census (C01).
QuestionKind = Literal["image", "attach", "project"]
#: Inc 10 (S-e): one unsaved item — ``(kind, raw unscrubbed name)``; the
#: ``document`` kind carries an empty name (the Patch Editor holds no file).
UnsavedItem = tuple[Literal["image", "document", "flow"], str]


@dataclass(frozen=True)
class ProjectLoadRequest:
    """Inc 12b (S-b): the project-load worker's immutable request, built on
    the main thread after the cheap refusals (LLR-177.1e / .1h)."""

    name: str
    project_dir: Path
    data_files: tuple[Path, ...]
    a2l_files: tuple[Path, ...]
    a2l_problem: Optional[ProjectFileProblem]
    a2l_cache: Optional[A2LCacheEntry]
    gen: int
    routed: bool


@dataclass(frozen=True)
class PreparedProjectLoad:
    """Inc 12b (S-b): the project worker's result; nothing in it is session
    until ``_install_prepared_project`` installs it (LLR-177.1f)."""

    request: ProjectLoadRequest
    refusal: Optional[str]
    variant_set: ProjectVariantSet
    manifest: Optional[ProjectManifest]
    problems: tuple[ProjectFileProblem, ...]
    a2l_cache: Optional[A2LCacheEntry]
    install: InstallSet
    image: Optional[LoadedFile]
    unreadable: tuple[VariantDescriptor, ...]
    mac: Optional[LoadedFile]
    document: Optional[RecordedDocumentState]


@dataclass(frozen=True)
class InstallSet:
    """
    Summary:
        What a project load installs (LLR-169.6, LED .34): the variant, the
        MAC and the A2L, as ``choose_install_set`` decides them.

    Args:
        variant (Optional[VariantDescriptor]): The variant to open, or
            ``None`` when no variant is left to try.
        mac (Optional[Path]): The project's MAC file, if any.
        a2l (Optional[Path]): The project's A2L file, if any.
    """

    variant: Optional[VariantDescriptor]
    mac: Optional[Path]
    a2l: Optional[Path]


def choose_install_set(
    variant_set: ProjectVariantSet,
    recorded: Optional[str],
    data_files: Sequence[Path],
    a2l_files: Sequence[Path],
    unreadable: Sequence[str] = (),
) -> InstallSet:
    """
    Summary:
        The fallback rule of a project load (LLR-169.6, LED .34), pure so the
        Load dialog's preview (Inc 9b) marks exactly what a load installs:
        the recorded active variant when it is valid, otherwise the next
        valid variant in ``build_variant_set`` order; then the MAC and A2L.

    Args:
        variant_set (ProjectVariantSet): The project's variants, in
            ``build_variant_set`` order.
        recorded (Optional[str]): The manifest's ``active_variant`` (``None``
            when none is recorded or the manifest is damaged or absent).
        data_files (Sequence[Path]): The project's data files (the MAC is
            taken from them).
        a2l_files (Sequence[Path]): The project's A2L files.
        unreadable (Sequence[str]): Variant ids the install already found
            not readable; they are skipped.

    Returns:
        InstallSet: The variant (``None`` when every variant is unreadable
            or there is none), the MAC and the A2L.

    Data Flow:
        - Start at the recorded variant when it is a variant of the project,
          else at the first; walk the variants in order, wrapping once.
        - The first variant not in ``unreadable`` wins. A missing recorded
          variant is never in the set, so the walk starts at the first.

    Dependencies:
        Used by:
            - S19TuiApp._handle_load_project
            - the Load dialog preview (Inc 9b)
    """
    variants = list(variant_set.variants)
    ids = [variant.variant_id for variant in variants]
    start = ids.index(recorded) if recorded in ids else 0
    skipped = set(unreadable)
    variant = next(
        (
            candidate
            for candidate in variants[start:] + variants[:start]
            if candidate.variant_id not in skipped
        ),
        None,
    )
    mac = next(
        (item for item in data_files if item.suffix.lower() in MAC_EXTENSIONS), None
    )
    return InstallSet(variant, mac, a2l_files[0] if a2l_files else None)

#: What each not-readable outcome means, in user terms (E3 R6, R16); the
#: exception class and the reader code go to the log only. The strings
#: live once, in the reader module (review F5).
_DOCUMENT_REASON: dict[str, str] = {
    DOCUMENT_LINK: DOCUMENT_REASON_LINK,
    DOCUMENT_TOO_LARGE: DOCUMENT_REASON_TOO_LARGE,
    DOCUMENT_UNREADABLE: DOCUMENT_REASON_UNREADABLE,
    DOCUMENT_IO_ERROR: DOCUMENT_REASON_IO_ERROR,
}
#: The next-step mark of the outcomes whose record Save project keeps
#: (E3 R16); the composer paints the step by this mark (review F5).
_DOCUMENT_STEP: dict[str, str] = {
    DOCUMENT_TOO_LARGE: STEP_OPEN_FROM_EDITOR,
    DOCUMENT_IO_ERROR: STEP_CHECK_THEN_LOAD,
}


#: The session-snapshot domain (HLR-165, LLR-165.2): every attribute name
#: ``S19TuiApp``'s own source assigns via ``self.<name> =``. The TEST
#: census re-derives the same set from the live source at run time and
#: fails the classification arm when the two drift (C-31: the domain is
#: derived, never trusted) — a new self-assignment lands here, or in the
#: test's declared exclusion list with its reason, never in neither.
#: Two Inc-era names carry an explicit classification because ARQ §2.2
#: has no row for them: ``_last_manifest_verify_result`` is INSTALL-OWNED
#: — every manifest verify rewrites it before its only reader consumes
#: it, so the reset seam must NOT clear it — and ``_variant_set_value``
#: is the backing store of the ``_variant_set`` property (row S5 covers
#: it: the seam assigns ``None`` through the setter, then the caller
#: adopts the manifest's set).
_SESSION_SNAPSHOT_NAMES: Tuple[str, ...] = (
    "_a2l_cache_data",
    "_a2l_cache_key",
    "_a2l_enriched_key",
    "_a2l_enriched_tags",
    "_a2l_filter_debounce_token",
    "_a2l_filtered_tags",
    "_a2l_row_key_to_tag",
    "_a2l_summary_lines",
    "_a2l_summary_start",
    "_a2l_tag_find_last_index",
    "_a2l_tag_find_query",
    "_a2l_tag_hex_highlight",
    "_a2l_window_start",
    "_active_screen_key",
    "_alt_first_visible_address",
    "_alt_goto_focus_address",
    "_change_service",
    "_declared_regions",
    "_diff_check_spec",
    "_diff_check_spec_name",
    "_diff_compare_generation",
    "_diff_last_result",
    "_goto_focus_address",
    "_hex_view_rows_cache",
    "_hex_window_start",
    "_image_generation",
    "_last_execution",
    "_last_flow_run",
    "_last_load_announcement",
    "_last_manifest_verify_result",
    "_last_template_path",
    "_mac_first_visible_address",
    "_mac_goto_focus_address",
    "_mac_row_key_to_address",
    "_mac_view_cache_cell_rows",
    "_mac_view_cache_cell_styles",
    "_mac_view_cache_coverage_line",
    "_mac_view_cache_key",
    "_mac_view_cache_meta",
    "_mac_view_cache_rows",
    "_mac_view_cache_summary",
    "_mac_view_cache_widths",
    "_mac_window_start",
    "_parsed_paste_text",
    "_pending_variant_id",
    "_report_filter_path",
    "_split_join_return_screen",
    "_validation_issues",
    "_validation_issues_window_start",
    "_validation_report",
    "_variant_set",
    "_variant_set_value",
    "a2l_tags_filter_field",
    "a2l_tags_filter_mode",
    "a2l_tags_filter_text",
    "a2l_tags_page_size",
    "base_dir",
    "current_a2l_data",
    "current_a2l_path",
    "current_file",
    "current_project",
    "current_project_dir",
    "hex_rows_page_size",
    "last_search_address",
    "last_search_text",
    "load_path",
    "log_lines",
    "logger",
    "mac_records_page_size",
    "validation_issue_filter_mode",
    "workarea",
)


class ProjectLoadMixin:

    def action_load_project(self) -> None:
        """Open the Load dialog on the project list (``p``)."""
        if self._refuse_if_busy():
            return
        self.logger.info("Load project action triggered.")
        self.push_screen(
            LoadDialog(
                mode="list",
                highlight=self.current_project,
                rows=self._load_dialog_rows,
                verdict=self._load_dialog_verdict,
                preview=self._load_dialog_preview,
            ),
            self._handle_load_dialog,
        )

    def _confirm_then_load(
        self, kind: QuestionKind, target: str, go: Callable[[], None]
    ) -> None:
        """Ask one replace question before unsaved work is replaced, or load.

        Summary:
            The one load seam (B100-I20, LLR-174.1 … LLR-174.4): ask the
            replace/cancel question when :meth:`_load_would_lose` reports
            unsaved work for ``kind``, else run ``go`` at once. Every route
            that may replace the loaded image — a project load, a typed or
            recent data/A2L load, a work-area pick and a variant switch —
            passes its continuation through here, so a load over unsaved
            work is never silent.

        Args:
            kind (QuestionKind): What the route may lose — ``image`` (the
                image only), ``attach`` (nothing) or ``project`` (image,
                document and flow).
            target (str): The raw on-disk name the route loads; the
                composer paints it (Q-2).
            go (Callable[[], None]): The load continuation; run at once
                when nothing is lost, else after a ``Replace`` answer on the
                next refresh (the question has popped by then).

        Returns:
            None

        Data Flow:
            - ``items = self._load_would_lose(kind)``; an empty list runs
              ``go()`` synchronously — no question, no log, no refresh
              deferral (the base timing of every route).
            - Otherwise compose ``(title, body)`` through
              ``_load_question_text`` and push ``ConfirmQuestionScreen``
              with the ``answer`` closure: ``True`` (Replace) defers ``go``
              through ``call_after_refresh``; ``False`` (Cancel, escape,
              enter on ``#confirm_no``; the modal never dismisses
              ``None``) re-homes the focus through
              ``_rehome_focus_after_load`` and paints nothing.
            - The seam never reads ``_dirty`` directly (LLR-174.1c) and
              holds no ``try/except``.

        Dependencies:
            Uses:
                - ``_load_would_lose`` / ``_load_question_text``
                - ``ConfirmQuestionScreen`` / ``push_screen``
                - ``_rehome_focus_after_load`` / ``call_after_refresh``
            Used by:
                - ``_route_load_project`` / ``_load_path_from_user_input``
                - ``_load_workarea_file`` / ``_handle_select_variant``
        """
        if self._refuse_if_busy():
            return
        items = self._load_would_lose(kind)
        if not items:
            go()
            return

        def answer(replace: bool) -> None:
            self.logger.info(
                "Load question answered: replace=%s kind=%s", bool(replace), kind
            )
            if replace:
                self.call_after_refresh(go)
            else:
                self._rehome_focus_after_load()

        title, body = self._load_question_text(kind, target, items)
        self.push_screen(
            ConfirmQuestionScreen(title, body, "Replace (y)", "Cancel (n)"), answer
        )

    def _load_would_lose(self, kind: QuestionKind) -> list[UnsavedItem]:
        """Enumerate the unsaved items a load of ``kind`` would replace.

        Summary:
            The load guard (E1 A2, LLR-174.1 … LLR-174.1c): read the three
            unsaved flags — D (the image differs from the last saved image),
            W (the Patch Editor holds unsaved entries) and F (the Flow
            Builder holds unsaved blocks) — and return the items a route of
            ``kind`` may lose, in the fixed order image, document, flow.
            The predicate reads state only and writes nothing.

        Args:
            kind (QuestionKind): What the route may lose.

        Returns:
            list[UnsavedItem]: The unsaved items in the fixed order; an
                ``attach`` route always returns ``[]`` (nothing is lost —
                the MAC/A2L attach keeps the image, the document and the
                flow, LLR-174.1a).

        Data Flow:
            - ``kind == "attach"`` returns ``[]`` without reading D, W or F.
            - ``cur = self.current_file``; D is
              ``differs_from_last_saved(cur.mem_map if cur is not None else
              None)`` — ``None`` yields ``False``, so the image item is
              appended only with a loaded image (LLR-174.1b).
            - ``kind == "project"`` additionally reads
              ``PatchEditorPanel.is_dirty`` (W) and
              ``FlowBuilderPanel.is_dirty`` / ``current_flow.name`` (F).
            - The order is image, document, flow; an ``image`` kind returns
              at most the image item.

        Dependencies:
            Uses:
                - ``ChangeService.differs_from_last_saved``
                - ``PatchEditorPanel.is_dirty`` / ``FlowBuilderPanel.is_dirty``
            Used by:
                - ``_confirm_then_load`` only
        """
        if kind == "attach":
            return []
        items: list[UnsavedItem] = []
        cur = self.current_file
        if self._change_service.differs_from_last_saved(
            cur.mem_map if cur is not None else None
        ):
            items.append(("image", cur.path.name))
        if kind == "project":
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
            if panel.is_dirty:
                items.append(("document", ""))
            flow = self.query_one("#flow_panel", FlowBuilderPanel)
            if flow.is_dirty:
                items.append(("flow", flow.current_flow.name))
        return items

    def _load_question_text(
        self, kind: QuestionKind, target: str, items: list[UnsavedItem]
    ) -> tuple[str, str]:
        """Compose the question's title and body (LLR-174.2i … LLR-174.2q).

        Summary:
            The composer (E1 A3, ruling Q-3): build the ``Replace <current>?``
            title and the two-sentence body from the unsaved items and the
            target, with every name passed through ``painted_names`` exactly
            once (Q-2 — the one scrub place). Pure over ``current_project``,
            ``current_file`` and the arguments; writes nothing.

        Args:
            kind (QuestionKind): What the route may lose; a ``project`` kind
                prefixes the painted target with ``project ``.
            target (str): The raw on-disk name the route loads.
            items (list[UnsavedItem]): The unsaved items to name, in order.

        Returns:
            tuple[str, str]: ``(title, body)`` — both plain painted ``str``
                (the screen paints them with markup off).

        Data Flow:
            - ``current`` is ``painted_names([current_project])``, else
              ``painted_names([current_file.path.name])``, else the literal
              ``the current session``; ``title = f"Replace {current}?"``.
            - Each item paints as ``image`` → the painted name,
              ``document`` → ``Patch Editor entries``, ``flow`` →
              ``flow <painted name>``.
            - ``joined`` is the single name, ``A and B`` for two, or
              ``A, B and C`` for three.
            - ``shown_target`` is ``project <painted target>`` for a project
              load, else the painted target.
            - ``body = f"There are unsaved changes in {joined}. Load
              {shown_target} anyway?"`` — the token ``unsaved changes`` once
              and two sentence ends outside names (LLR-174.2q).

        Dependencies:
            Uses:
                - ``painted_names``
            Used by:
                - ``_confirm_then_load`` only
        """
        if self.current_project:
            current = painted_names([self.current_project])
        elif self.current_file is not None:
            current = painted_names([self.current_file.path.name])
        else:
            current = "the current session"
        title = f"Replace {current}?"
        names: list[str] = []
        for item_kind, name in items:
            if item_kind == "image":
                names.append(painted_names([name]))
            elif item_kind == "document":
                names.append("Patch Editor entries")
            else:
                names.append(f"flow {painted_names([name])}")
        if len(names) == 1:
            joined = names[0]
        else:
            joined = ", ".join(names[:-1]) + " and " + names[-1]
        shown_target = (
            f"project {painted_names([target])}"
            if kind == "project"
            else painted_names([target])
        )
        body = f"There are unsaved changes in {joined}. Load {shown_target} anyway?"
        return title, body

    def _route_load_project(self, name: str) -> None:
        """
        Summary:
            The Load project dialog's router (LLR-178.3): ask the replace
            question when the project load would lose unsaved work, then run
            the project load and open the Load-result panel when this load
            composed an announcement. A direct ``_handle_load_project`` call
            (tests, fixtures) meets no question and no modal.

        Args:
            name (str): The picked project's on-disk name.

        Returns:
            None

        Data Flow:
            - The seam is here (S-d): ``go`` is the load body below, passed
              to ``_confirm_then_load`` so ``_handle_load_project`` asks
              nothing and runs only after a ``Replace`` answer. After 12b
              the project install handler pushes the Load-result panel
              (LLR-177.1h): the base ``before`` / identity test and the push
              after the call are deleted.

        Dependencies:
            Uses:
                - ``_confirm_then_load`` / ``_handle_load_project``
            Used by:
                - ``_handle_load_dialog`` (the ``project`` kind) and
                  ``_load_path_from_user_input`` (the project arm)
        """
        self._confirm_then_load(
            "project", name, lambda: self._handle_load_project(name, routed=True)
        )

    def _load_dialog_rows(self) -> list[tuple[str, str, Optional[LoadChoice]]]:
        """
        Summary:
            The Load dialog's ``rows`` callable (S-c): build every
            ``(section_id, painted plain label, choice)`` triple in list
            order — the projects section, then work-area files, then recent
            sources (LLR-173.4l). Each section starts with a heading row
            (``choice None``) and holds either loadable rows or one token
            line (``choice None``).

        Returns:
            list[tuple[str, str, Optional[LoadChoice]]]: The rows; a ``None``
            choice marks a heading or token line (the dialog disables it).

        Data Flow:
            - Projects: ``list_projects()``; an ``OSError`` paints the
              ``could not be read`` token line (LLR-173.4m), ``0`` names
              paint ``no projects — ctrl+s saves a project``, else one row
              per on-disk name with ``LoadChoice("project", name)``.
            - Work area: ``list_workarea_files`` filtered by ``recent_kind``
              (the one lister, CR9-11); ``0`` files paint
              ``no work-area files — l loads a file``.
            - Recents: ``read_recent_sources`` (never raises); a ``problem``
              paints ``<problem> — <next step>`` (LLR-173.4g), ``0`` entries
              paint ``no recent sources``, else one row per entry with the
              file name and kind (LLR-173.4h) and ``LoadChoice("recent",
              path)``. Every label goes through ``painted_names``.

        Dependencies:
            Uses:
                - ``list_projects`` / ``list_workarea_files`` / ``recent_kind``
                - ``read_recent_sources`` / ``_RECENT_PROBLEM_STEPS``
                - ``painted_names`` / ``PureWindowsPath``
            Used by:
                - ``LoadDialog`` on mount (through ``action_load_file`` /
                  ``action_load_project``)
        """
        rows: list[tuple[str, str, Optional[LoadChoice]]] = []
        rows.append(("projects", "Projects", None))
        try:
            names = self.list_projects()
        except OSError:
            rows.append(
                (
                    "projects",
                    "could not be read — check that the folder can be opened, then load again",
                    None,
                )
            )
        else:
            if names:
                for name in names:
                    rows.append(
                        ("projects", painted_names([name]), LoadChoice("project", name))
                    )
            else:
                rows.append(("projects", "no projects — ctrl+s saves a project", None))
        rows.append(("workarea", "Work area", None))
        files = [
            p for p in list_workarea_files(self.workarea) if recent_kind(p) is not None
        ]
        if files:
            for path in files:
                rows.append(
                    ("workarea", painted_names([path.name]), LoadChoice("workarea", path.name))
                )
        else:
            rows.append(("workarea", "no work-area files — l loads a file", None))
        rows.append(("recent", "Recent", None))
        store = read_recent_sources()
        if store.problem is not None:
            rows.append(
                (
                    "recent",
                    f"{store.problem} — {_RECENT_PROBLEM_STEPS[store.problem]}",
                    None,
                )
            )
        elif not store.entries:
            rows.append(("recent", "no recent sources", None))
        else:
            for entry in store.entries:
                label = f"{painted_names([PureWindowsPath(entry.path).name])} ({entry.kind})"
                rows.append(("recent", label, LoadChoice("recent", entry.path)))
        return rows

    def _load_dialog_verdict(self, choice: LoadChoice) -> Optional[tuple[str, str]]:
        """
        Summary:
            The Load dialog's ``verdict`` callable (S-b): ``None`` means
            "go"; otherwise the ``(reason_token, step_token)`` pair the
            dialog paints in ``#load_reason`` and stays open. It reads
            metadata only (S-e), paints nothing and writes nothing.

        Args:
            choice (LoadChoice): The loadable row's choice, or the typed
                ``path`` choice built by the dialog (S-a).

        Returns:
            Optional[tuple[str, str]]: ``None`` to dismiss, else the
            refusal-token pair from ``_TYPED_REFUSAL_TOKENS``.

        Data Flow:
            - ``project`` / ``workarea`` -> ``None`` (a project pick is
              refused, if it must be, by ``_handle_load_project``).
            - ``path`` / ``recent`` -> ``_typed_load_route(Path(value))``;
              a non-``refuse`` action -> ``None``, else the mapped tokens.
              A recent goes through the same classifier (LLR-173.4k).
            - No ``try/except`` (R-5): ``_typed_load_route`` maps every
              ``OSError`` itself.

        Dependencies:
            Uses:
                - ``_typed_load_route`` / ``_TYPED_REFUSAL_TOKENS``
            Used by:
                - ``LoadDialog`` load request (``enter``, ``alt+l``,
                  ``#load_ok``)
        """
        if choice.kind in ("project", "workarea"):
            return None
        action, reason = self._typed_load_route(Path(choice.value))
        if action != "refuse":
            return None
        return _TYPED_REFUSAL_TOKENS[reason]

    def _load_dialog_preview(self, choice: LoadChoice) -> list[tuple[str, bool]]:
        """
        Summary:
            The Load dialog's ``preview`` callable (S-b): build the
            ``(painted plain text, marked)`` lines for one choice, returned
            synchronously for every kind (Q2 / A9b-04).

        Args:
            choice (LoadChoice): The highlighted row's choice (never a typed
                ``path`` — A9b-07 removed the typed-file arm).

        Returns:
            list[tuple[str, bool]]: The lines; the dialog prefixes ``● ``
            only where ``marked`` is true.

        Data Flow:
            - ``recent`` -> the full recorded path, its kind and
              ``checked when loaded``, 0 marks and 0 filesystem calls
              (LLR-173.4i / LLR-173.4j).
            - ``workarea`` -> ``_file_preview_marks`` over session state
              and the file name, no filesystem call.
            - ``path`` -> ``[]`` (no typed-file preview).
            - ``project`` -> a synchronous build from the link-safe scan
              (R2-N2), the ``project.json`` lstat regular-file gate (S9b-2),
              ``read_project_manifest`` / ``build_variant_set`` /
              ``choose_install_set`` and ``_a2l_admission`` (A9b-R2-6); an
              ``OSError`` paints the ``could not be read`` token line
              (LLR-173.6k).

        Dependencies:
            Uses:
                - ``_list_project_files`` / ``_a2l_admission``
                - ``read_project_manifest`` / ``manifest_is_damaged``
                - ``build_variant_set`` / ``choose_install_set``
                - ``_file_preview_marks`` / ``recent_kind`` / ``painted_names``
            Used by:
                - ``LoadDialog`` on a highlight
        """
        if choice.kind == "recent":
            value = choice.value
            return [
                (painted_names([value], clip=len(value)), False),
                (f"kind {recent_kind(Path(value))}", False),
                ("checked when loaded", False),
            ]
        if choice.kind == "workarea":
            return self._file_preview_marks(self.workarea / WORKAREA_TEMP / choice.value)
        if choice.kind == "path":
            return []
        # project
        folder = self.workarea / choice.value
        try:
            data_files, a2l_files, cardinality_error = self._list_project_files(folder)
            manifest_path = folder / PROJECT_MANIFEST_NAME
            try:
                manifest_stat = deps.os.lstat(manifest_path)
            except FileNotFoundError:
                manifest_stat = None
            # SEC9b-2: the ``_folder_holds_project`` test (regular and not a
            # reparse point), so a placeholder is refused before any open.
            if manifest_stat is not None and (
                not stat.S_ISREG(manifest_stat.st_mode)
                or deps._is_reparse_point(manifest_path)
            ):
                return [
                    (
                        "could not be read — check that the folder can be opened, then load again",
                        False,
                    )
                ]
            manifest = (
                deps.read_project_manifest(folder) if manifest_stat is not None else None
            )
            variant_set = build_variant_set(choice.value, data_files)
            recorded = (
                manifest.active_variant
                if manifest is not None and not manifest_is_damaged(manifest)
                else None
            )
            a2l_ok = bool(a2l_files) and self._a2l_admission(a2l_files[0]) is None
            install_a2l = a2l_files[0] if a2l_ok else None
            install = choose_install_set(
                variant_set,
                recorded,
                data_files,
                [install_a2l] if install_a2l is not None else [],
            )
            if cardinality_error is not None:
                # A9b-R2-3 / R2-N1: more than one MAC or A2L refuses the
                # install, so every mark is ``False`` (0 ``●``).
                install = InstallSet(None, None, None)
            lines: list[tuple[str, bool]] = []
            marked_variant_id = (
                install.variant.variant_id if install.variant is not None else None
            )
            for variant in variant_set.variants:
                lines.append(
                    (
                        f"variant {painted_names([variant.path.name])}",
                        variant.variant_id == marked_variant_id,
                    )
                )
            for mac in (
                item for item in data_files if item.suffix.lower() in MAC_EXTENSIONS
            ):
                lines.append((f"MAC {painted_names([mac.name])}", mac == install.mac))
            if a2l_files:
                lines.append(
                    (
                        f"A2L {painted_names([a2l_files[0].name])}",
                        a2l_ok and install.a2l is not None,
                    )
                )
            if manifest is None:
                state = "no project.json"
            elif manifest_is_damaged(manifest):
                state = "manifest damaged"
            else:
                state = "ok"
            lines.append((f"project file: {state}", False))
            return lines
        except OSError:
            return [
                (
                    "could not be read — check that the folder can be opened, then load again",
                    False,
                )
            ]

    def _file_preview_marks(self, path: Path) -> list[tuple[str, bool]]:
        """
        Summary:
            The work-area file row's preview marks (LLR-173.6b / LLR-173.6c):
            pure over session state and the file name, run on the event loop
            with no filesystem call. It encodes the install rule the Load
            session keeps (image, MAC and A2L).

        Args:
            path (Path): The work-area file's full path.

        Returns:
            list[tuple[str, bool]]: The marked / unmarked lines.

        Data Flow:
            - S19/HEX: ``● image``; the kept MAC and A2L; a project-open
              note ``becomes the active variant of project <name>``
              (LLR-173.6c).
            - MAC: the kept image (an overlay keeps the image), ``● MAC``
              and the kept A2L; no project note.
            - A2L: the kept image and MAC, ``● A2L``; no note.

        Dependencies:
            Uses:
                - ``painted_names`` / ``PROJECT_PRIMARY_DATA_EXTENSIONS``
                - ``MAC_EXTENSIONS`` (an A2L suffix is the fallback arm)
            Used by:
                - ``_load_dialog_preview`` (the ``workarea`` kind)
        """
        cur = self.current_file
        kept_a2l = self.current_a2l_path or (cur.a2l_path if cur else None)
        suffix = path.suffix.lower()
        lines: list[tuple[str, bool]] = []
        if suffix in PROJECT_PRIMARY_DATA_EXTENSIONS:
            lines.append((f"image {painted_names([path.name])}", True))
            if cur and cur.mac_path:
                lines.append((f"MAC {painted_names([cur.mac_path.name])}", True))
            if kept_a2l:
                lines.append((f"A2L {painted_names([kept_a2l.name])}", True))
            if self.current_project:
                lines.append(
                    (
                        f"becomes the active variant of project "
                        f"{painted_names([self.current_project])}",
                        False,
                    )
                )
            return lines
        if suffix in MAC_EXTENSIONS:
            if cur and cur.file_type in {"s19", "hex"}:
                lines.append((f"image {painted_names([cur.path.name])}", True))
            lines.append((f"MAC {painted_names([path.name])}", True))
            if kept_a2l:
                lines.append((f"A2L {painted_names([kept_a2l.name])}", True))
            return lines
        # A2L
        if cur and cur.file_type in {"s19", "hex"}:
            lines.append((f"image {painted_names([cur.path.name])}", True))
        if cur and cur.mac_path:
            lines.append((f"MAC {painted_names([cur.mac_path.name])}", True))
        lines.append((f"A2L {painted_names([path.name])}", True))
        return lines

    def _handle_load_result(self, choice: Optional[str]) -> None:
        """
        Summary:
            Close the Load-result panel (LLR-178.3); ``v`` /
            ``#result_variant`` then opens the existing variant selector.
            The focus needs no move here (LLR-166.1): the load tail
            re-homes the main screen's focus behind the panel, and closing
            the panel restores that focus.

        Args:
            choice (Optional[str]): ``LOAD_RESULT_SELECT_VARIANT`` or
                ``None``.

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_select_variant``
            Used by:
                - ``_route_load_project`` (the panel's dismiss callback)
        """
        if choice == LOAD_RESULT_SELECT_VARIANT:
            self.action_select_variant()

    def _reset_project_session(self) -> None:
        """
        Summary:
            Reset every piece of session state a project load must not
            carry over from the outgoing session (HLR-165 / LLR-165.1,
            the PH-2 seam): the loaded image with its MAC and A2L
            attachments (ARQ §2.2 S1), the A2L path and parsed data
            (S2/S3), the variant ids (S5), the declared regions (S6), the
            last CRC template (S7), the last comparison and check spec
            (S8), the last flow run and execution (S9/S10), the report
            filter (S11), the A2L derived views (S12), the MAC view
            caches, the view-row memo (``_hex_view_rows_cache``, CR-1),
            the validation report and issues and the row-key maps
            (S13 plus A-07's eleven probe names). The change service is
            REBOUND to a new object (S4) — nothing outside this module
            holds the old one (P-26), so a new ``ChangeService()`` is
            complete by construction — and the monotonic image generation
            the app owns is re-pushed into it (LLR-165.3). The monotonic
            counters ``_image_generation`` / ``_diff_compare_generation``
            (K1) — and the batch-102 Inc 2 A2L attach generation, which
            the S2/S3 clear bumps through ``_replace_current_a2l`` rather
            than resetting — and the view preferences, the log deque,
            the active rail screen and the path-keyed A2L parse cache
            (K2) are KEPT.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reset S1-S13 in place (S4 last but for the rebind, S13
              through ``_invalidate_mac_view_cache`` plus the four probe
              names the invalidator does not own), and ``None`` the
              view-row memo ``_hex_view_rows_cache`` with S1.
            - Repaint the Patch panel through ``refresh_entries`` — the
              reset is the one place a load can leave the panel holding a
              previous project's document, and the panel's retain
              semantics keep the stale rows without this render. A
              not-yet-mounted tree (headless unit tests) is tolerated,
              matching ``_apply_empty_state`` / the load install tail.
            - The panel's public ``clear_paste_buffer()`` then
              ``mark_loaded()`` (LED .55(b), LED .60): the reset discards
              the outgoing document — including entries the panel's
              dirty marker or paste buffer still describe — so both are
              cleared with it, synchronously; the buffer clear posts no
              ``TextArea.Changed`` that could re-set the marker.
              Otherwise the panel would paint ``0 entries ●`` over the
              empty ledger and the Load guard would ask about nothing.

        Dependencies:
            Uses:
                - ``ChangeService`` / ``_invalidate_mac_view_cache`` /
                  ``_strip_source_map`` / ``_patch_document_view``
                - ``PatchEditorPanel.clear_paste_buffer`` /
                  ``PatchEditorPanel.mark_loaded``
            Used by:
                - ``_handle_load_project`` — the ONE caller (LLR-165.1).
        """
        # S1: the loaded image (carries mac_path / mac_records / a2l_* /
        # mem_map). ``None`` before the first install, so the primary
        # parse's MAC merge sees no existing file (P-2's ``LEAK
        # mac_records``).
        self.current_file = None
        # Inc 10a (E5, CR-1): a writer of ``current_file`` that bumps no image
        # generation resets the view-row memo (``_hex_view_rows``).
        self._hex_view_rows_cache = None
        # S2/S3: the A2L path and parsed payload — the two parse
        # fallbacks a loose-S19 reload would otherwise re-attach (P-2's
        # ``LEAK a2l_tags``; ``current_a2l_data``'s clearing writer is
        # LLR-165.4's unload arm, :meth:`_apply_unload`). Routed through
        # ``_replace_current_a2l``, the single-writer seam (batch-102
        # Inc 2): its generation bump is harmless — the counter is
        # monotonic and K1-like, never reset — and its cache clear
        # overlaps S12/S13 below.
        self._replace_current_a2l(None, None)
        # S5: variant ids — the caller adopts the manifest's set after
        # the reset.
        self._variant_set = None
        self._pending_variant_id = None
        # S6: declared regions — the caller adopts the manifest's value
        # after the reset.
        self._declared_regions = ()
        # S7: the last CRC template (a latent cross-project gather, ARQ
        # §2.2 row S7).
        self._last_template_path = None
        # S8: the last comparison and check spec.
        self._diff_last_result = None
        self._diff_check_spec = None
        self._diff_check_spec_name = ""
        # S9/S10: the last flow run and execution.
        self._last_flow_run = None
        self._last_execution = None
        # S11: the sticky report-filter selection.
        self._report_filter_path = None
        # S12: the A2L derived views (enriched/filtered tags, summary,
        # window, find state).
        self._a2l_enriched_tags = []
        self._a2l_enriched_key = None
        self._a2l_filtered_tags = []
        self._a2l_window_start = 0
        self._a2l_summary_lines = []
        self._a2l_summary_start = 0
        self._a2l_tag_find_query = ""
        self._a2l_tag_find_last_index = -1
        # S13 + A-07's probe names: the MAC view caches (all eight
        # ``_mac_view_cache_*`` rows the invalidator already owns — the
        # ARQ §2.2 inventory text still says "seven"; it predates
        # ``_mac_view_cache_widths``), the validation report and issues,
        # and the per-DataTable row-key maps.
        self._invalidate_mac_view_cache()
        self._validation_report = None
        self._validation_issues = []
        self._mac_row_key_to_address = {}
        self._a2l_row_key_to_tag = {}
        # S4: the change service. A rebind, not a ``reset()`` method
        # (the rejected alternative would add change_service.py to this
        # increment and stay complete only until the next field is
        # added): the new object carries an empty document, empty
        # undo/redo, no journal and no saved-state stamps by
        # construction. The app's monotonic image generation — a K1
        # counter the seam must NOT reset — is pushed into the new
        # service exactly as the install point does (LLR-165.3).
        self._change_service = ChangeService()
        self._change_service.set_image_generation(self._image_generation)
        # The paste text the outgoing document was parsed from goes with it
        # (LED .72 Q2): the buffer is cleared below.
        self._parsed_paste_text = None
        # Repaint the Patch panel through refresh_entries (LLR-165.1) —
        # the empty-session call shape ``_refresh_patch_history_view``
        # uses; without it the panel would keep painting the outgoing
        # project's document until the next install's deferred chain.
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            # App not mounted (headless unit tests drive the load
            # pipeline on a bare tree) — the same tolerance the load
            # install tail documents; the service-side rebind above is
            # set either way.
            pass
        else:
            panel.refresh_entries(
                self._change_service.rows(None),
                mem_map=self._strip_source_map(None),
                document=self._patch_document_view(),
            )
            # LED .55(b): the outgoing document is gone — entries AND the
            # dirty marker / paste buffer that described it. The panel
            # clears its buffer without posting TextArea.Changed, so
            # writer w2 never re-sets the dirty flag and mark_loaded runs
            # now — deferring it raced that message (hotfix 3b: a clean
            # session then raised the dirty-load question).
            panel.clear_paste_buffer()
            panel.mark_loaded()
            self.refresh_bindings()
            # Inc 6 (R-TUI-049.3.1/.3.2): the reset discards the document,
            # so the old apply's controls go; the fresh service has no run.
            self._hide_replaced_document_controls(panel)
            self._refresh_patch_checks_tab(panel)
        # Inc 6 (E3A-02, R-CHKS-009): a displayed Checks screen repaints
        # with the reset run state (a guarded no-op when not mounted).
        self.update_checks_view()

    def _session_snapshot(self) -> dict:
        """
        Summary:
            The normalised projection of the session state this class's
            own source assigns (HLR-165 / LLR-165.2, the B100-I19 seam):
            one comparable entry per name in
            :data:`_SESSION_SNAPSHOT_NAMES` — the source census the test
            re-derives at run time (C-31), minus the test's declared
            exclusion list. Values are normalised so that two sessions
            over the same facts compare equal: paths become relative to
            ``base_dir``; the ``current_file`` payload becomes
            ``(type, relative path, image digest)`` whose digest feeds
            ``address:byte`` pairs; the change service becomes its public
            counts; plain dicts reduce to ``(len, sorted keys, digest of
            the normalised values)`` so two payloads over the same key
            set never compare equal; the stat-/identity-keyed caches drop
            their mtime / ``id()`` components (QA R2-07); every other
            object becomes a count, a key list or a type name.

        Args:
            None

        Returns:
            dict: ``name -> normalised value`` for every name in the
                domain. Nothing here is a live reference: mutating the
                returned dict touches no app state.

        Data Flow:
            - Walk the declared domain with ``getattr(self, name, None)``.
            - Normalise by value kind (see Summary); the three keyed
              caches (``_mac_view_cache_key``, ``_a2l_cache_key``,
              ``_a2l_enriched_key``) get named reductions whose shapes
              are documented at their builders
              (``_mac_view_cache_key_for`` / ``_load_a2l_data_with_cache``
              / ``_compute_a2l_enriched_tags``).

        Dependencies:
            Used by:
                - ``tests/test_b100_session_reset.py`` (TC-B100-09): the
                  cold-load vs load-over leak comparison.
        """
        base = self.base_dir

        def _rel(path: Path) -> str:
            try:
                return path.relative_to(base).as_posix()
            except ValueError:
                return path.as_posix()

        def _image_digest(mem_map: dict) -> str:
            # Address AND byte: hashing the bytes in address order alone
            # cannot see WHICH addresses hold them (the reviewer's F9:
            # two images that differ only in placement would compare
            # equal).
            digest = hashlib.sha256()
            for address in sorted(mem_map):
                digest.update(str(address).encode("utf-8"))
                digest.update(b":")
                digest.update(bytes((mem_map[address] & 0xFF,)))
            return digest.hexdigest()

        def _norm(value: Any) -> Any:
            if value is None or isinstance(value, (bool, int)):
                return value
            if isinstance(value, Path):
                return _rel(value)
            if isinstance(value, str):
                base_text = str(base)
                if base_text in value:
                    return value.replace(base_text, ".")
                return value
            if isinstance(value, LoadedFile):
                return ("LoadedFile", _rel(value.path), _image_digest(value.mem_map))
            if isinstance(value, ChangeService):
                depths = value.history_depths()
                return (
                    "ChangeService",
                    len(value.document.entries),
                    depths["back"],
                    depths["forward"],
                )
            if isinstance(value, dict):
                # Content reduction, not keys alone (the reviewer's F9):
                # the A2L payloads (``current_a2l_data``,
                # ``_a2l_cache_data``) are dicts with FIXED section keys,
                # so a keys-only reduction compared two different
                # payloads EQUAL. Reduce to the length, the sorted keys
                # and a digest of the normalised values in key order.
                keys = sorted(value, key=str)
                payload = repr([_norm(value[key]) for key in keys]).encode(
                    "utf-8"
                )
                return (
                    len(value),
                    [str(key) for key in keys],
                    hashlib.sha256(payload).hexdigest(),
                )
            if isinstance(value, (deque, list, tuple, set, frozenset)):
                return [_norm(item) for item in value]
            return type(value).__name__

        snapshot: dict[str, Any] = {}
        for name in _SESSION_SNAPSHOT_NAMES:
            value = getattr(self, name, None)
            if name == "_mac_view_cache_key":
                # Identity-keyed cache (shape: ``(records_identity,
                # len(records), id(a2l_data), file_type, ranges_tuple,
                # mem_map_len)`` — ``_mac_view_cache_key_for``): the
                # id() components carry no comparable state; the counts
                # and kinds are the leak signal (QA R2-07).
                snapshot[name] = (
                    None
                    if value is None
                    else ("mac-view-cache", value[1], value[3], _norm(value[4]), value[5])
                )
            elif name == "_a2l_cache_key":
                # Stat-keyed cache (shape: ``(resolved path, mtime_ns,
                # size)`` — ``_load_a2l_data_with_cache``): the mtime is
                # filesystem noise between two loads of one file; keep
                # the path and size (QA R2-07).
                snapshot[name] = (
                    None
                    if value is None
                    else ("a2l-cache", _norm(value[0]), value[2])
                )
            elif name == "_a2l_enriched_key":
                # Generation-keyed cache (shape: ``(a2l_view_generation,
                # image_generation, mem_size)`` — batch-102 Inc 2,
                # ``_compute_a2l_enriched_tags``): the two generation
                # components are monotonic counters (K1-like) that a
                # load-over may move, like ``_image_generation``; keep
                # the comparable half, the memory map size (QA R2-07).
                snapshot[name] = (
                    None if value is None else ("a2l-enriched", value[2])
                )
            elif name == "_hex_view_rows_cache":
                # Generation-and-MAC-set-keyed cache (shape: ``(key, rows)``
                # — Inc 10a, ``_hex_view_rows``): the key carries the
                # monotonic image generation and a frozenset, both of which
                # a load-over may move; keep the comparable half, the view
                # row list (QA R2-07).
                snapshot[name] = None if value is None else _norm(value[1])
            else:
                snapshot[name] = _norm(value)
        return snapshot

    def _handle_load_project(self, name: Optional[str], routed: bool = False) -> None:
        """The project-load kickoff (12b): cheap refusals, the request, the worker."""
        if self._refuse_if_busy():
            return
        if name is None:
            self.logger.info("Load project canceled.")
            return
        project_dir = self.workarea / name
        # LLR-171.4e / LLR-171.4f: a picked folder that is a link, is not
        # one folder of this work area, or resolves outside it is refused
        # before ``exists()`` (which follows a junction) and before any
        # reset.
        folder_reason = self._project_folder_refusal(project_dir)
        if folder_reason is not None:
            painted = painted_names([name])
            if folder_reason == "link":
                message = (
                    f"Project NOT loaded: '{painted}' is a link or junction — "
                    "pick a project in the list."
                )
            elif folder_reason == "unreadable":
                reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
                message = f"Project NOT loaded: '{painted}' {reason} — {step}."
            else:
                message = (
                    f"Project NOT loaded: '{painted}' is outside the work area — "
                    "copy the folder into the work area."
                )
            self.set_status(safe_text(message).plain)
            self.logger.warning("Project load refused (%s): %r", folder_reason, name)
            return
        if not project_dir.exists():
            self.set_status(safe_text(f"Project not found: {painted_names([name])}").plain)
            self.logger.warning("Project not found: %s", name)
            return
        # LLR-172.5g / E3 R3: a name the project list does not list (by
        # ``normcase``) is refused before ``validate_project_files`` and the
        # reset, so a reserved home, a stream/8.3/trailing-dot spelling and a
        # case-different name all stop here; a match loads the on-disk name.
        try:
            match = self._listed_project_name(name)
        except OSError:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"Project NOT loaded: '{painted_names([name])}' {reason} — {step}."
                ).plain
            )
            self.logger.warning("Project load refused (could not be read): %r", name)
            return
        if match is None:
            reason, step = _TYPED_REFUSAL_TOKENS["not a project"]
            self.set_status(
                safe_text(
                    f"Project NOT loaded: '{painted_names([name])}' is {reason} — {step}."
                ).plain
            )
            self.logger.warning("Project load refused (not listed): %r", name)
            return
        name = match
        project_dir = self.workarea / name
        # R2-N2: the one link-safe listing (LLR-173.4n), shared with the
        # preview, replaces ``validate_project_files`` here so a linked
        # child is neither listed nor installed. F-12 / LLR-173.1g: an
        # unreadable picked project paints one status line and returns.
        try:
            data_files, a2l_files, error = self._list_project_files(project_dir)
        except OSError:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"Project NOT loaded: '{painted_names([name])}' {reason} — {step}."
                ).plain
            )
            self.logger.warning("Project load refused (could not be read): %r", name)
            return
        if error:
            self.set_status(error)
            self.logger.warning("Project validation failed: %s", error)
            return
        # R5 / LLR-171.2f / LLR-171.2g: the project's A2L is parsed only
        # when it is a regular file within the placement's size cap (read
        # at call time). Without a data file the load is refused before the
        # reset; beside a data file the A2L is left out for every consumer
        # and named as a problem.
        a2l_problem: Optional[ProjectFileProblem] = None
        if a2l_files:
            # A9b-R2-6: the one A2L admission rule, shared with the preview,
            # so the A2L the preview marks is exactly the A2L the install
            # keeps (HLR-173a).
            a2l_reason = self._a2l_admission(a2l_files[0])
            if a2l_reason is not None:
                self.logger.warning(
                    "Project A2L not readable: %r (%s)",
                    str(a2l_files[0]), a2l_reason,
                )
            if a2l_reason is not None and not data_files:
                self.set_status(
                    safe_text(
                        f"Project NOT loaded: {painted_names([a2l_files[0].name])} "
                        f"in '{painted_names([name])}' {a2l_reason} — replace the "
                        "A2L file, then Load again."
                    ).plain
                )
                self.logger.warning(
                    "Project load refused: A2L %r %s", str(a2l_files[0]), a2l_reason
                )
                return
            if a2l_reason is not None:
                # F2 (LLR-171.2g): Save project does not drop the A2L, so the
                # painted step is "replace the A2L file, then Load again".
                a2l_problem = ProjectFileProblem(
                    PROBLEM_NOT_READABLE,
                    a2l_files[0].name,
                    a2l_reason.removeprefix("is "),
                    step=STEP_REPLACE_A2L,
                )
                a2l_files = []
        # LLR-171.2d / LLR-171.2e: a folder with neither a data file nor an
        # A2L file is refused before the reset; an A2L-only folder goes on.
        if not data_files and not a2l_files:
            try:
                has_manifest = stat.S_ISREG(
                    deps.os.lstat(project_dir / PROJECT_MANIFEST_NAME).st_mode
                )
            except OSError:
                has_manifest = False
            if has_manifest:
                message = (
                    f"Project NOT loaded: '{painted_names([name])}' has no data or "
                    "A2L file — load a file and Save project."
                )
            else:
                message = (
                    f"Project NOT loaded: '{painted_names([name])}' has no "
                    "project.json — load a file and Save project."
                )
            self.set_status(safe_text(message).plain)
            self.logger.warning("No data or A2L file in project: %r", name)
            return
        # S9b-2: the lstat regular-file gate on ``project.json`` runs before
        # any manifest read AND before the reset — a FIFO, link or directory
        # is refused here with 0 opens (R2-N5) and the session unchanged
        # (B99); an absent file keeps the 9a "no project.json" path.
        manifest_path = project_dir / PROJECT_MANIFEST_NAME
        try:
            manifest_stat = deps.os.lstat(manifest_path)
        except FileNotFoundError:
            manifest_stat = None
        except OSError:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"Project NOT loaded: '{painted_names([name])}' {reason} — {step}."
                ).plain
            )
            self.logger.warning("Project load refused (manifest unreadable): %r", name)
            return
        # SEC9b-2: the same test as ``_folder_holds_project`` and the preview.
        if manifest_stat is not None and (
            not stat.S_ISREG(manifest_stat.st_mode) or deps._is_reparse_point(manifest_path)
        ):
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"Project NOT loaded: '{painted_names([name])}' {reason} — {step}."
                ).plain
            )
            self.logger.warning(
                "Project load refused (manifest not a regular file): %r", name
            )
            return
        gen = self._busy_begin_action("project_load", name)
        # E3 S12b-04: while the project load runs, the paste buffer is read-only.
        try:
            text_area = self.query_one("#patch_paste_text", TextArea)
        except Exception:  # noqa: BLE001 - not mounted (headless tests)
            text_area = None
        if text_area is not None:
            text_area.read_only = True
        try:
            request = ProjectLoadRequest(
                name,
                project_dir,
                tuple(data_files),
                tuple(a2l_files),
                a2l_problem,
                self._a2l_cache_entry(),
                gen,
                routed,
            )
            self._project_load_worker(request)
        except BaseException:
            self._busy_fail("project_load", gen)
            raise

    @work(thread=True, group="project_load")
    def _project_load_worker(self, request: ProjectLoadRequest) -> None:
        """The project-load worker (S-b / S-d): prepare, then hand the result."""
        try:
            try:
                prepared = self._prepare_project_load(request)
            except Exception as exc:  # noqa: BLE001 - worker-step failures
                self.logger.exception("Project load failed on the worker: %r", request.name)
                self.call_from_thread(self._on_project_load_failed, request, exc)
                return
            self.call_from_thread(self._on_project_loaded, prepared)
        except BaseException:
            self.call_from_thread(self._busy_fail, "project_load", request.gen)
            raise

    def _prepare_project_load(self, request: ProjectLoadRequest) -> PreparedProjectLoad:
        """The project-load worker step: reads only the request (LLR-177.1e)."""
        data = list(request.data_files)
        a2l_files = list(request.a2l_files)
        variant_set = build_variant_set(request.name, data)
        manifest = deps.read_project_manifest(request.project_dir)
        problems = deps.check_project_files(request.project_dir, manifest)
        for problem in problems:
            self.logger.warning(
                "Project %s: %s %s (%s)",
                request.name, problem.kind, problem.file, problem.code,
            )
        if request.a2l_problem is not None:
            problems.append(request.a2l_problem)
        recorded = (
            manifest.active_variant
            if manifest is not None and not manifest_is_damaged(manifest)
            else None
        )
        a2l_context: Optional[dict] = None
        a2l_cache: Optional[A2LCacheEntry] = None
        if a2l_files:
            self.call_from_thread(self.step_busy, "project_load", request.gen, 2)
            try:
                entry = deps.parse_a2l_cached(
                    a2l_files[0],
                    request.a2l_cache,
                    progress=self._progress_forwarder("project_load", request.gen, 2),
                )
                a2l_context, a2l_cache = entry[1], entry
            except Exception as exc:  # noqa: BLE001 - an untrusted A2L file
                self.logger.warning(
                    "Project A2L not readable: %s (%s)",
                    a2l_files[0], type(exc).__name__,
                )
                problems.append(
                    ProjectFileProblem(
                        PROBLEM_NOT_READABLE,
                        a2l_files[0].name,
                        "the file cannot be read",
                    )
                )
                a2l_files = []
                a2l_cache = None
        install = choose_install_set(variant_set, recorded, data, a2l_files)
        if install.variant is None and install.mac is None and install.a2l is None:
            self.logger.warning("No loadable data file in project: %s", request.name)
            return PreparedProjectLoad(
                request,
                f"No supported files in project: {painted_names([request.name])}",
                variant_set,
                manifest,
                tuple(problems),
                a2l_cache,
                install,
                None,
                (),
                None,
                None,
            )
        document: Optional[RecordedDocumentState] = None
        if (
            manifest is not None
            and not manifest_is_damaged(manifest)
            and manifest.active_document is not None
        ):
            text = manifest.active_document
            state = deps.recorded_document_state(request.project_dir, text, a2l_context)
            if state.outcome != DOCUMENT_MISSING:
                if state.outcome != DOCUMENT_OK:
                    self.logger.warning(
                        "Project change document not reopened: %s %s (%s)",
                        text, state.outcome, state.detail,
                    )
                    problems.append(
                        ProjectFileProblem(
                            PROBLEM_NOT_READABLE,
                            document_problem_file(text),
                            _DOCUMENT_REASON[state.outcome],
                            step=_DOCUMENT_STEP.get(state.outcome),
                        )
                    )
                else:
                    state.document.source_path = request.project_dir.absolute() / text
                    document = state
        self.call_from_thread(self.step_busy, "project_load", request.gen, 3)
        a2l_path = a2l_files[0] if a2l_files else None
        a2l_data = a2l_context if a2l_files else None
        unreadable: list[VariantDescriptor] = []
        image: Optional[LoadedFile] = None
        while install.variant is not None:
            try:
                loaded = self._parse_data_file(install.variant.path, a2l_path, a2l_data, None)
            except Exception:  # noqa: BLE001 - an untrusted image file
                self.logger.warning(
                    "Project image not readable: %s", install.variant.path
                )
                loaded = None
            if loaded is None:
                reason = "not an S19 or HEX file"
            elif not loaded.mem_map:
                reason = "not an S19 or HEX file" if loaded.errors else "0 data bytes"
            else:
                reason = None
            if reason is not None:
                unreadable.append(install.variant)
                problems.append(
                    ProjectFileProblem(
                        PROBLEM_NOT_READABLE, install.variant.path.name, reason
                    )
                )
                install = choose_install_set(
                    variant_set,
                    recorded,
                    data,
                    a2l_files,
                    [variant.variant_id for variant in unreadable],
                )
                continue
            image = loaded
            break
        opened = install.variant
        variant_set.active_id = opened.variant_id if opened is not None else None
        if image is not None:
            image.variant_id = opened.variant_id
        mac: Optional[LoadedFile] = None
        if install.mac is not None:
            mac = self._parse_data_file(install.mac, a2l_path, a2l_data, image)
        return PreparedProjectLoad(
            request,
            None,
            variant_set,
            manifest,
            tuple(problems),
            a2l_cache,
            install,
            image,
            tuple(unreadable),
            mac,
            document,
        )

    def _on_project_loaded(self, prepared: PreparedProjectLoad) -> None:
        """Main thread: paint step 4 then defer the install (LLR-176.3)."""
        gen = prepared.request.gen
        if prepared.refusal is not None:
            self._quit_pending = False
            self.end_busy("project_load", gen, prepared.refusal)
            return
        self.step_busy("project_load", gen, 4)
        self.call_after_refresh(self._install_prepared_project, prepared)

    def _install_prepared_project(self, prepared: PreparedProjectLoad) -> None:
        """
        Summary:
            Install a prepared project atomically and publish its final
            image/MAC/A2L state once under the incoming project identity.

        Args:
            prepared (PreparedProjectLoad): Parsed project artifacts and manifest
                produced by the project worker.

        Returns:
            None

        Data Flow:
            - Build image/MAC bundles and reject keyed stale bundles before reset.
            - Install each bundle without intermediate A2L publication; close
              every superseded exit with kept-state text and no success outcome.
            - Publish the common fan-out once, then retain announcement/result
              behavior and defer the successful busy outcome.

        Dependencies:
            Uses:
                - ``_apply_prepared_load`` / ``_refresh_a2l_dependent_views``
                - ``compose_load_announcement`` / ``end_busy``
            Used by:
                - ``_on_project_loaded`` on the UI thread
        """
        request = prepared.request
        gen = request.gen
        image_bundle = (
            PreparedLoad(loaded=prepared.image) if prepared.image is not None else None
        )
        mac_bundle = (
            PreparedLoad(loaded=prepared.mac) if prepared.mac is not None else None
        )
        for bundle in (image_bundle, mac_bundle):
            if bundle is None or bundle.a2l_enriched_key is None:
                continue
            actual = (bundle.a2l_view_generation, bundle.a2l_image_generation)
            expected = (
                self._a2l_view_generation + int(bool(bundle.loaded.a2l_data)),
                self._image_generation + 1,
            )
            if actual != expected:
                self.end_busy(
                    "project_load", gen, "Load superseded — current state kept."
                )
                return
        try:
            self._reset_project_session()
            self._declared_regions = (
                tuple(prepared.manifest.declared_regions)
                if prepared.manifest is not None
                else ()
            )
            if prepared.a2l_cache is not None:
                self._store_a2l_cache(prepared.a2l_cache)
            install = prepared.install
            if install.variant is None and install.mac is None:
                self._replace_current_a2l(
                    install.a2l,
                    prepared.a2l_cache[1] if prepared.a2l_cache is not None else None,
                )
                self._apply_empty_state()
            self._reopen_active_document(prepared.document)
            self.current_project = request.name
            self.current_project_dir = request.project_dir
            # Inc 6 (E3A-04): the lists depend on the open project; refill
            # once the new project is assigned.
            self._refill_document_lists()
            self._variant_set = prepared.variant_set
            if image_bundle is not None:
                self._pending_variant_id = install.variant.variant_id
                if not self._apply_prepared_load(
                    image_bundle,
                    install.variant.path,
                    time.perf_counter(),
                    publish_a2l=False,
                ):
                    self.end_busy(
                        "project_load", gen, "Load superseded — current state kept."
                    )
                    return
            if mac_bundle is not None and not self._apply_prepared_load(
                mac_bundle,
                install.mac,
                time.perf_counter(),
                publish_a2l=False,
            ):
                self.end_busy(
                    "project_load", gen, "Load superseded — current state kept."
                )
                return
            self._refresh_a2l_dependent_views()
            loaded = self.current_file
            announcement = deps.compose_load_announcement(
                request.name,
                prepared.variant_set,
                prepared.manifest,
                mac_name=(
                    loaded.mac_path.name
                    if loaded is not None and loaded.mac_path is not None
                    else None
                ),
                a2l_name=(
                    self.current_a2l_path.name if self.current_a2l_path else None
                ),
                problems=list(prepared.problems),
                unreadable=[variant.path.name for variant in prepared.unreadable],
            )
            self._last_load_announcement = announcement
            self.set_file_status(safe_text(announcement.status_line()).plain)
            self.logger.info(
                "Project loaded. name=%s file=%s mac=%s",
                request.name,
                install.variant.path if install.variant is not None else None,
                install.mac,
            )
            self.update_project_labels()
            self._publish_flow_session_dir()
            # R2-F1: a confirmed quit exits in ``end_busy`` below; a result
            # screen pushed now would mount over a closing app.
            if request.routed and not self._quit_pending:
                self.push_screen(LoadResultScreen(announcement), self._handle_load_result)
            self.call_after_refresh(
                self.end_busy,
                "project_load",
                gen,
                safe_text(announcement.summary_line()).plain,
            )
        except BaseException:
            self._busy_fail("project_load", gen)
            raise

    def _on_project_load_failed(
        self, request: ProjectLoadRequest, exc: BaseException
    ) -> None:
        """Main thread: the ``could not be read`` failure end (LLR-177.2)."""
        self.logger.warning(
            "Project load not installed: %r (%s)", request.name, type(exc).__name__
        )
        self._quit_pending = False
        self.end_busy(
            "project_load",
            request.gen,
            safe_text(
                f"Project NOT loaded: '{painted_names([request.name])}' could not "
                "be read — check that the folder can be opened, then load again."
            ).plain,
        )
