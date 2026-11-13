"""s19_app.tui.app.file_load — S19TuiApp mixin: file_load (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePath
import stat
import time
from typing import Any, List, Optional, Tuple
from textual import work
from textual.widgets import ListItem, ListView
from ...range_index import address_in_sorted_ranges
from ...render.hexview import build_row_bases
from ...utils import safe_text
from ..mac import parse_mac_file
from ..models import LoadedFile
from ..screens import ConfirmQuestionScreen, LoadChoice, LoadDialog
from ..services.a2l_service import enrich_tags_and_render
from ..services.project_gather_service import painted_names
from ..services import folder_open_service
from .. import workspace
from ..workspace import (
    A2L_EXTENSIONS,
    MAC_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    contained_in_workarea,
    list_workarea_files,
    record_recent_source,
    recent_kind,
)
from . import deps
from .shared import (
    _TYPED_REFUSAL_TOKENS,
    A2LCacheEntry,
    PreparedLoad,
    precompute_mac_datatable_payload,
)


@dataclass(frozen=True)
class A2LAttachRequest:
    """Inc 12b (S-b): the A2L attach worker's immutable request."""

    source: Path
    copy: bool
    temp_dir: Path
    workarea: Path
    record_recent: bool
    a2l_cache: Optional[A2LCacheEntry]
    gen: int
    sync_project: bool = True


@dataclass(frozen=True)
class A2LAttachResult:
    """Inc 12b (S-b): the A2L attach worker's result (copy_seconds dropped,
    E3 A12b-04)."""

    request: A2LAttachRequest
    path: Path
    entry: A2LCacheEntry
    parse_seconds: float


class FileLoadMixin:

    def refresh_files(self) -> None:
        """Refresh the Workarea Files list from the temp load folder.

        Every file load copies into ``workarea/temp`` (HLR-162 / LLR-162.3,
        CW-U-3), so that — never the work-area root, never the private
        ``temp/.staging`` home — is the folder this list reads. The rows come
        from ``list_workarea_files`` (LLR-172.4, seam S3): the regular,
        non-link direct children of ``workarea/temp``, sorted, or ``[]``
        when the folder is missing or cannot be listed. Each row paints its
        name through ``painted_names`` (the one category scrub — Cc, Cf, Zl
        and Zp removed, an unpaired surrogate as U+FFFD, clipped to 120
        characters) with markup off through ``safe_text`` (LLR-172.6, E3 R4);
        ``item.data`` keeps the on-disk name, which ``_load_from_item`` reads
        (LLR-172.6a, C5). Only names whose suffix a loader accepts are listed
        (``recent_kind``, the predicate the Load dialog's files section reads;
        LLR-172.4f), so a sidecar dump such as ``x.a2l.json`` is not offered.
        """
        list_view = self.query_one("#files_list", ListView)
        list_view.clear()
        files = [
            p for p in list_workarea_files(self.workarea) if recent_kind(p) is not None
        ]
        for path in files:
            entry = deps.ListItem(deps.Label(safe_text(painted_names([path.name]))))
            entry.data = path.name
            list_view.append(entry)
        self.logger.info("Workarea refreshed. files=%d", len(files))

    def action_refresh_files(self) -> None:
        self.refresh_files()

    def action_load_file(self) -> None:
        """Open the Load dialog on the typed-path field (``l`` / ``ctrl+l``)."""
        if self._refuse_if_busy():
            return
        self.logger.info("Load file action triggered.")
        self.push_screen(
            LoadDialog(
                mode="path",
                highlight=self.current_project,
                rows=self._load_dialog_rows,
                verdict=self._load_dialog_verdict,
                preview=self._load_dialog_preview,
            ),
            self._handle_load_dialog,
        )

    def action_open_workarea(self) -> None:
        """Open the workarea directory in the platform's file manager.

        Rides the one cross-platform open seam (LLR-139.3,
        ``folder_open_service.open_folder_in_file_manager``) — the shipped
        ``subprocess.Popen(["explorer", …])`` idiom generalized per platform —
        with ``label="workarea"`` so the ``o``-key status text stays
        byte-identical (``Opened workarea: …`` / ``Failed to open workarea:
        …``). The seam lands its own failures on the status line; only the
        log tail stays here.
        """
        opened = folder_open_service.open_folder_in_file_manager(
            self.workarea,
            set_status=self.set_status,
            label="workarea",
        )
        if opened:
            self.logger.info("Opened workarea in explorer: %s", self.workarea)
        else:
            self.logger.error("Failed to open workarea.")

    def _typed_load_route(self, path: Path) -> Tuple[str, str]:
        """
        Summary:
            Classify one user-typed Load path into an action and a reason
            word, reading only metadata (HLR-172a, LLR-172.5): a project,
            a data file, an A2L file, or a refusal. It never paints, never
            writes, and never raises: every ``OSError``, and the ``OSError`` /
            ``ValueError`` / ``RuntimeError`` of a text the path calls refuse
            (a NUL, EACCES, ENAMETOOLONG), becomes a reason.

        Args:
            path (Path): The path typed into the Load dialog (or the
                start-up ``load_path``).

        Returns:
            Tuple[str, str]: ``("project", name)`` with ``name`` the on-disk
                name of a listed project; ``("data", "")``; ``("a2l", "")``;
                or ``("refuse", reason)`` with ``reason`` one of
                ``not found``, ``not a supported file``, ``not a project``,
                ``outside``, ``link``, ``link file``, ``unreadable``.

        Data Flow:
            - A relative typed path keeps the file route only (step 0): a
              folder is refused ``not a supported file`` (LLR-172.5h), so the
              base-folder fallback's resolved path never feeds the project
              route.
            - An absolute path is matched lexically against this work area
              (``os.path.abspath``, no ``resolve``), walked with ``os.lstat``
              for links/junctions, matched by ``normcase`` against
              ``list_projects`` (the on-disk spelling is routed, E3 R3), then
              tested for project content (§1.3).
            - A link on the walk refuses ``link``; when the typed path names
              a data or A2L file (not ``project.json``) it refuses
              ``link file`` instead (CR9b-03).

        Dependencies:
            Uses:
                - ``resolve_input_path`` / ``list_projects``
                - ``_folder_holds_project`` / ``_is_reparse_point``
            Used by:
                - ``_load_path_from_user_input`` / ``_load_dialog_verdict``
        """
        text = str(path).strip().strip('"')
        try:
            normalized = deps.resolve_input_path(path, self.base_dir)
        except (OSError, ValueError, RuntimeError):
            # S12a-01 / SEC9b-1: a path too long for the OS (``ValueError``), a
            # POSIX ``~user`` with no home (``RuntimeError``), or an OS error
            # (EACCES / ENAMETOOLONG) is refused, never raised.
            return ("refuse", "not found")
        if normalized is None:
            return ("refuse", "not found")
        if not Path(text).is_absolute():
            if deps.os.path.isdir(normalized):
                return ("refuse", "not a supported file")
            suffix = normalized.suffix.lower()
            if suffix in A2L_EXTENSIONS:
                return ("a2l", "")
            if suffix in SUPPORTED_EXTENSIONS:
                return ("data", "")
            return ("refuse", "not a supported file")

        typed = deps.os.path.abspath(normalized)
        w = deps.os.path.abspath(self.workarea)
        ntyped = deps.os.path.normcase(typed)
        nw = deps.os.path.normcase(w)
        inside = ntyped == nw or ntyped.startswith(nw + deps.os.sep)
        parts: List[str]
        if inside:
            if ntyped == nw:
                parts = []
            else:
                parts = typed[len(w):].lstrip(deps.os.sep).split(deps.os.sep)
        else:
            parts = []
        is_manifest = PurePath(typed).name.casefold() == "project.json"
        # CR9-3: the suffix the loaders test; ``abspath`` drops a trailing dot.
        suffix = normalized.suffix.lower()

        if not inside:
            if is_manifest:
                return ("refuse", "outside")
            if deps.os.path.isdir(typed):
                return ("refuse", "outside")
            if suffix in A2L_EXTENSIONS:
                return ("a2l", "")
            if suffix in SUPPORTED_EXTENSIONS:
                return ("data", "")
            return ("refuse", "not a supported file")

        last_stat: Optional[os.stat_result] = None
        for i in range(1, len(parts) + 1):
            prefix = deps.os.path.join(w, *parts[:i])
            try:
                st_info = deps.os.lstat(prefix)
            except FileNotFoundError:
                return ("refuse", "not found")
            except OSError:
                return ("refuse", "unreadable")
            if stat.S_ISLNK(st_info.st_mode) or deps._is_reparse_point(Path(prefix)):
                if not is_manifest and (
                    suffix in A2L_EXTENSIONS or suffix in SUPPORTED_EXTENSIONS
                ):
                    return ("refuse", "link file")
                return ("refuse", "link")
            last_stat = st_info

        # S9b-7: the data / A2L returns are taken only after the lstat walk
        # shows a regular file; a folder named ``x.s19`` then reaches the
        # project route below (S9b-7 R2).
        if (
            not is_manifest
            and last_stat is not None
            and stat.S_ISREG(last_stat.st_mode)
        ):
            if suffix in A2L_EXTENSIONS:
                return ("a2l", "")
            if suffix in SUPPORTED_EXTENSIONS:
                return ("data", "")

        if is_manifest:
            folder_parts = parts[:-1]
        else:
            if last_stat is not None and not stat.S_ISDIR(last_stat.st_mode):
                return ("refuse", "not a supported file")
            folder_parts = parts

        if len(folder_parts) != 1:
            return ("refuse", "not a project")
        typed_name = folder_parts[0]

        try:
            name = self._listed_project_name(typed_name)
        except OSError:
            return ("refuse", "unreadable")
        if name is None:
            return ("refuse", "not a project")

        folder = self.workarea / name
        # F-3: the one §1.3 test (Q7), lifted into ``_folder_holds_project``
        # so the list, the pick match and the typed route share one definition.
        held = self._folder_holds_project(folder)
        if held is True:
            return ("project", name)
        if held is None:
            return ("refuse", "unreadable")
        return ("refuse", "not a project")

    def _load_path_from_user_input(self, path: Path) -> None:
        """
        Summary:
            Route a user-typed path through the classifier and dispatch to a
            project, data or A2L load, or paint one refusal status line
            (HLR-172a, LLR-172.5b–.5f/.5h).

        Args:
            path (Path): The path typed into the Load dialog.

        Returns:
            None

        Data Flow:
            - ``_typed_load_route`` reads only metadata and returns
              ``(action, value)``.
            - ``typed = Path(str(path).strip().strip('"'))`` — the same
              strip the classifier and ``resolve_input_path`` apply (F-1,
              P-1); the loaders still receive the raw ``path``.
            - ``project`` -> ``_route_load_project`` (asked there, LLR-174.4a).
            - ``a2l`` -> ``_confirm_then_load`` with ``attach`` (an A2L
              attach keeps the image and asks nothing).
            - ``data`` -> the kind and the target name come from the path
              ``resolve_input_path`` returns, the one ``load_from_path``
              reads (CR10-01 / SEC10-01): ``attach`` (a MAC attach keeps the
              image) only when that suffix is a MAC suffix AND equals the
              typed suffix; otherwise ``image``, so the question asks.
            - ``refuse`` -> one status line from the six reason words, the
              typed text through ``painted_names`` with markup off; no
              question (LLR-174.4b race arm).

        Dependencies:
            Uses:
                - ``_typed_load_route`` / ``_route_load_project``
                - ``_confirm_then_load``
                - ``load_a2l_from_path`` / ``load_from_path``
            Used by:
                - ``on_mount`` / ``_handle_load_dialog``
        """
        action, value = self._typed_load_route(path)
        typed = Path(str(path).strip().strip('"'))
        if action == "project":
            self._route_load_project(value)
            return
        if action == "a2l":
            self._confirm_then_load(
                "attach", typed.name, lambda: self.load_a2l_from_path(path)
            )
            return
        if action == "data":
            # CR10-01 / SEC10-01: the relative fallback's ``resolve()``
            # follows a link, so a typed ``.mac`` can name an image; a
            # typed suffix that differs from the resolved one fails closed.
            # SE5-12a-4: an OS error here falls to the typed name; the
            # loader's own use-time look then refuses it.
            try:
                resolved = deps.resolve_input_path(path, self.base_dir)
            except (OSError, ValueError, RuntimeError):
                resolved = None
            suffix = resolved.suffix.lower() if resolved is not None else ""
            kind = (
                "attach"
                if suffix in MAC_EXTENSIONS and suffix == typed.suffix.lower()
                else "image"
            )
            self._confirm_then_load(
                kind,
                (resolved or typed).name,
                lambda: self.load_from_path(path),
            )
            return
        t = painted_names([str(path)])
        if value == "not found":
            line = f"File NOT loaded: '{t}' not found — check the path."
        elif value == "not a supported file":
            line = f"File NOT loaded: '{t}' is not a supported file — check the path."
        elif value == "not a project":
            reason, step = _TYPED_REFUSAL_TOKENS["not a project"]
            line = f"Project NOT loaded: '{t}' is {reason} — {step}."
        elif value == "outside":
            line = (
                f"Project NOT loaded: '{t}' is outside the work area — copy "
                "the folder into the work area."
            )
        elif value == "link":
            line = (
                f"Project NOT loaded: '{t}' passes through a link or junction — "
                "pick a project in the list."
            )
        elif value == "link file":
            line = (
                f"File NOT loaded: '{t}' is a link or junction — open the "
                "file it points to."
            )
        else:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            line = f"Project NOT loaded: '{t}' {reason} — {step}."
        self.set_status(safe_text(line).plain)
        self.logger.warning("Typed load refused (%s): %r", value, str(path))

    def _handle_load_dialog(self, result: Optional[LoadChoice]) -> None:
        """
        Summary:
            The one Load dialog router (LLR-173.1e): receive a
            :class:`LoadChoice` or ``None`` (escape / Cancel) and defer the
            actual load work so Textual can process the screen-pop message
            before any blocking code runs.

        Args:
            result (Optional[LoadChoice]): The dialog's one result — the
                ``kind`` / ``value`` pair — or ``None`` on cancel.

        Returns:
            None

        Data Flow:
            - ``None`` -> ``_rehome_focus_after_load`` (LLR-166.1, A9b-03),
              then return with the session unchanged.
            - Log a ``modal_dismiss_scheduled`` phase boundary and flush.
            - Dispatch through ``call_after_refresh`` so the modal-pop
              message processes first: ``project`` -> ``_route_load_project``;
              ``workarea`` -> ``_load_workarea_file``; ``path`` / ``recent``
              -> ``_load_path_from_user_input(Path(value))``. ``LoadKind`` is
              a closed ``Literal``, so there is no else arm.

        Dependencies:
            Uses:
                - ``_route_load_project`` / ``_load_workarea_file``
                - ``_load_path_from_user_input`` / ``_flush_logger``
                - ``_rehome_focus_after_load`` / ``call_after_refresh``
            Used by:
                - ``action_load_file`` / ``action_load_project``
        """
        if result is None:
            self._rehome_focus_after_load()
            return
        self.logger.info(
            "Load phase boundary: modal_dismiss_scheduled kind=%s value=%r",
            result.kind,
            result.value,
        )
        self._flush_logger()
        # Defer the load so Textual's pop_screen message queued by Screen.dismiss()
        # is processed first; otherwise the modal stays visible for the duration of
        # the copy/parse/install pipeline because dismiss() invokes this callback
        # synchronously before scheduling the pop.
        if result.kind == "project":
            self.call_after_refresh(self._route_load_project, result.value)
        elif result.kind == "workarea":
            self.call_after_refresh(self._load_workarea_file, result.value)
        else:
            self.call_after_refresh(self._load_path_from_user_input, Path(result.value))

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
        if self._refuse_if_busy():
            return
        self.logger.info("Load phase boundary: dialog_callback_entry path=%s", path)
        self._flush_logger()
        # SE5-12a-4: the use-time look (after the Inc 10 question) refuses an
        # OS-refused path as not found instead of raising out of a callback.
        try:
            normalized = deps.resolve_input_path(path, self.base_dir)
        except (OSError, ValueError, RuntimeError):
            normalized = None
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
        gen = self._busy_begin_action("file_load", normalized.name)
        try:
            self.logger.info("Load phase boundary: copy_started path=%s", normalized)
            self._flush_logger()
            copy_started = time.perf_counter()
            try:
                copied = deps.copy_into_workarea(
                    normalized, temp_dir, workarea_root=self.workarea
                )
            except WorkareaContainmentError as exc:
                self._pending_variant_id = None
                self.end_busy("file_load", gen, f"Cannot load file: {exc}")
                self.logger.warning("Load rejected by workarea guard: %s", exc)
                return
            copy_elapsed = time.perf_counter() - copy_started
            self.logger.info(
                "Load phase boundary: copy_done path=%s elapsed=%.3fs",
                copied.name,
                copy_elapsed,
            )
            self._flush_logger()
            # LLR-172.1n (CR9-1): a source found only through the relative
            # fallback is not recorded (the fallback's ``resolve()`` follows a
            # link, against LLR-172.1a). ``via_fallback`` is pure — no
            # filesystem call — because ``resolve_input_path`` returns the
            # typed candidate unchanged when it exists, so the result is
            # relative exactly when the typed text is relative.
            typed = Path(str(path).strip().strip('"')).expanduser()
            via_fallback = normalized.is_absolute() and not typed.is_absolute()
            if (
                not contained_in_workarea(normalized, self.workarea)
                and not via_fallback
            ):
                if not record_recent_source(normalized):
                    self.logger.warning(
                        "Recent sources not updated: %r", str(normalized)
                    )
            elif not contained_in_workarea(normalized, self.workarea):
                self.logger.info(
                    "Recent source not recorded (found through the fallback): %r",
                    str(normalized),
                )
            self.step_busy("file_load", gen, 2)
            # Kick the worker off before anything else so the modal-dismiss
            # callback yields control back to the event loop promptly.
            # Workarea refresh + diagnostic log are dispatched via
            # ``call_later`` so they run on the next idle frame.
            copied_size = copied.stat().st_size
            self._start_load_worker(copied, gen=gen)

            def _post_worker_launch() -> None:
                self.refresh_files()
                self.logger.info(
                    "File copied to temp: path=%s size_bytes=%d copy_seconds=%.3f",
                    copied,
                    copied_size,
                    copy_elapsed,
                )
                self.logger.info(
                    "Load phase boundary: worker_spawned path=%s", copied.name
                )
                self._flush_logger()

            self.call_later(_post_worker_launch)
        except BaseException:
            self._busy_fail("file_load", gen)
            raise

    def load_a2l_from_path(self, path: Path, *, copy: bool = True) -> None:
        """
        Summary:
            Admit an A2L source, confirm replacement of a project's sole A2L,
            and delegate every accepted load to the common worker kickoff.

        Args:
            path (Path): Original source path used for messages and recents.
            copy (bool): Whether the worker copies the admitted source.

        Returns:
            None

        Data Flow:
            - Refuse busy, missing and unsupported sources before inspection.
            - Preserve project validation errors; ask before replacing one A2L.
            - Delegate admissible loads with project sync enabled by default.

        Dependencies:
            Uses:
                - ``_confirm_project_a2l_replacement`` / ``_start_a2l_load``
            Used by:
                - A2L load dialog and Workarea source routes
        """
        if self._refuse_if_busy():
            return
        try:  # SE5-12a-4, as in load_from_path
            normalized = deps.resolve_input_path(path, self.base_dir)
        except (OSError, ValueError, RuntimeError):
            normalized = None
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
                try:  # CR12b-2: the open project's folder can vanish outside the app
                    _, a2l_files, error = deps.validate_project_files(project_dir)
                except OSError:
                    reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
                    self.set_status(
                        safe_text(
                            f"A2L NOT loaded: project "
                            f"'{painted_names([self.current_project])}' {reason} — {step}."
                        ).plain
                    )
                    self.logger.warning(
                        "A2L load refused (project folder could not be read): %r",
                        project_dir,
                    )
                    return
                if error:
                    self.set_status(error)
                    self.logger.warning("Project validation failed: %s", error)
                    return
                if len(a2l_files) == 1:
                    self._confirm_project_a2l_replacement(
                        path,
                        normalized,
                        copy=copy,
                        project_name=self.current_project,
                        project_dir=project_dir,
                        project_a2l=a2l_files[0],
                    )
                    return
            else:
                self.logger.warning("current_project set but project directory could not be resolved; skipping project guard.")
        self._start_a2l_load(path, normalized, copy=copy)

    def _confirm_project_a2l_replacement(
        self,
        path: Path,
        normalized: Path,
        *,
        copy: bool,
        project_name: str,
        project_dir: Path,
        project_a2l: Path,
    ) -> None:
        """
        Summary:
            Ask before replacing a project's A2L and revalidate the captured
            identity before starting a session-only confirmed replacement.

        Args:
            path (Path): Original candidate path.
            normalized (Path): Admitted candidate path.
            copy (bool): Whether the normal worker copies the candidate.
            project_name (str): Project named by the question.
            project_dir (Path): Captured lexical project directory.
            project_a2l (Path): Captured sole project A2L.

        Returns:
            None

        Data Flow:
            - Push one Yes/No question without copying, parsing or mutating.
            - On Yes, defer a busy check and project/A2L identity revalidation.
            - Start the ordinary worker with project sync disabled only after
              both identities still match; No and Escape are inert.

        Dependencies:
            Uses:
                - ``ConfirmQuestionScreen`` / ``validate_project_files``
                - ``_start_a2l_load``
            Used by:
                - ``load_a2l_from_path``
        """
        painted_project = painted_names([project_name])
        painted_current = painted_names([project_a2l.name])
        painted_new = painted_names([path.name])
        body = (
            f"Project '{painted_project}' already has A2L '{painted_current}'. "
            f"Load '{painted_new}' instead?"
        )

        def _accepted() -> None:
            if self._refuse_if_busy():
                return
            changed_message = (
                "A2L NOT loaded: project or its A2L changed — load again."
            )
            if self.current_project != project_name:
                self.set_status(changed_message)
                return
            current_dir = self._active_project_dir()
            if current_dir is None or deps.os.path.normcase(
                deps.os.path.abspath(current_dir)
            ) != deps.os.path.normcase(deps.os.path.abspath(project_dir)):
                self.set_status(changed_message)
                return
            try:
                _, a2l_files, error = deps.validate_project_files(current_dir)
            except OSError:
                reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
                self.set_status(
                    safe_text(
                        f"A2L NOT loaded: project "
                        f"'{painted_names([project_name])}' {reason} — {step}."
                    ).plain
                )
                self.logger.warning(
                    "A2L load refused (project folder could not be read): %r",
                    current_dir,
                )
                return
            if error:
                self.set_status(error)
                self.logger.warning("Project validation failed: %s", error)
                return
            if len(a2l_files) != 1 or deps.os.path.normcase(
                deps.os.path.abspath(a2l_files[0])
            ) != deps.os.path.normcase(deps.os.path.abspath(project_a2l)):
                self.set_status(changed_message)
                return
            self._start_a2l_load(
                path, normalized, copy=copy, sync_project=False
            )

        def _answer(accepted: bool) -> None:
            if accepted:
                self.call_after_refresh(_accepted)

        self.push_screen(
            ConfirmQuestionScreen(
                "Replace project A2L?", body, "Yes (y)", "No (n)"
            ),
            _answer,
        )

    def _start_a2l_load(
        self,
        path: Path,
        normalized: Path,
        *,
        copy: bool,
        sync_project: bool = True,
    ) -> None:
        """
        Summary:
            Start one normal A2L worker after source checks and a final busy
            boundary shared by ordinary and confirmed loads.

        Args:
            path (Path): Original source path used for messages and recents.
            normalized (Path): Admitted source used for stat, copy and parse.
            copy (bool): Whether the worker copies the admitted source.
            sync_project (bool): Whether successful install may sync the project.

        Returns:
            None

        Data Flow:
            - Preserve source-size, large-file and recent-source behavior.
            - Recheck busy immediately before creating the busy run/request.
            - Create one immutable attach request and start one worker.

        Dependencies:
            Uses:
                - ``A2LAttachRequest`` / ``_a2l_attach_worker``
            Used by:
                - ``load_a2l_from_path`` / confirmed project replacement
        """
        try:  # CR12b-2: never a size of 0, so the over-cap rule is not bypassed
            source_size = normalized.stat().st_size
        except OSError:
            self.set_status(f"A2L file not found: {path}")
            self.logger.warning("A2L file not found: %s", path)
            return
        if source_size >= self.large_a2l_warn_bytes:
            self.logger.warning(
                "Large A2L detected before copy: path=%s size_bytes=%d threshold_bytes=%d",
                normalized,
                source_size,
                self.large_a2l_warn_bytes,
            )
        # The recent decision, on the main thread (post-9b rule); the store
        # itself moves to the install handler (P2-9 / F-5).
        typed = Path(str(path).strip().strip('"')).expanduser()
        via_fallback = normalized.is_absolute() and not typed.is_absolute()
        outside = not contained_in_workarea(normalized, self.workarea)
        record = outside and not via_fallback
        if outside and via_fallback:
            self.logger.info(
                "Recent source not recorded (found through the fallback): %r",
                str(normalized),
            )
        if self._refuse_if_busy():
            return
        gen = self._busy_begin_action("a2l_load", normalized.name)
        try:
            request = A2LAttachRequest(
                source=normalized,
                copy=copy,
                temp_dir=self.workarea / WORKAREA_TEMP,
                workarea=self.workarea,
                record_recent=record,
                a2l_cache=self._a2l_cache_entry(),
                gen=gen,
                sync_project=sync_project,
            )
            if not copy:
                self.step_busy("a2l_load", gen, 2)
            self._a2l_attach_worker(request)
        except BaseException:
            self._busy_fail("a2l_load", gen)
            raise

    @work(thread=True, group="a2l_load")
    def _a2l_attach_worker(self, request: A2LAttachRequest) -> None:
        """The A2L attach worker (S-b / S-d): copy (unless in place) + parse."""
        try:
            try:
                started = time.perf_counter()
                if request.copy:
                    path = deps.copy_into_workarea(
                        request.source, request.temp_dir, workarea_root=request.workarea
                    )
                    copy_seconds = time.perf_counter() - started
                    self.logger.info(
                        "A2L copy complete: path=%s size_bytes=%d copy_seconds=%.3f",
                        path, path.stat().st_size, copy_seconds,
                    )
                    self.call_from_thread(self.step_busy, "a2l_load", request.gen, 2)
                else:
                    path = request.source
                parse_started = time.perf_counter()
                entry = deps.parse_a2l_cached(
                    path,
                    request.a2l_cache,
                    progress=self._progress_forwarder("a2l_load", request.gen, 2),
                )
                result = A2LAttachResult(
                    request, path, entry, time.perf_counter() - parse_started
                )
            except Exception as exc:  # noqa: BLE001 - worker-step failures
                if not isinstance(exc, WorkareaContainmentError):
                    self.logger.exception("A2L attach failed: %s", request.source)
                self.call_from_thread(self._on_a2l_attach_failed, request, exc)
                return
            self.call_from_thread(self._on_a2l_attached, result)
        except BaseException:
            self.call_from_thread(self._busy_fail, "a2l_load", request.gen)
            raise

    def _on_a2l_attached(self, result: A2LAttachResult) -> None:
        """Main thread: paint step 3, defer the tag-table build (LLR-176.3)."""
        self.step_busy("a2l_load", result.request.gen, 3)
        self.call_after_refresh(self._install_attached_a2l, result)

    def _install_attached_a2l(self, result: A2LAttachResult) -> None:
        """
        Summary:
            Install a parsed A2L, publish every dependent view and defer the
            successful outcome behind the detail-card barrier.

        Args:
            result (A2LAttachResult): Immutable request, parsed cache entry and
                worker timing for one accepted attach.

        Returns:
            None

        Data Flow:
            - Preserve recents, cache, current-A2L and current-file attach order.
            - Run the common fan-out once, then retain labels/focus/logging.
            - Sync to a project only for requests that explicitly allow it.

        Dependencies:
            Uses:
                - ``_replace_current_a2l`` / ``_refresh_a2l_dependent_views``
                - ``_sync_loaded_a2l_to_project`` / ``end_busy``
            Used by:
                - ``_on_a2l_attached`` on the UI thread
        """
        req = result.request
        copied = result.path
        gen = req.gen
        try:
            if req.record_recent and not record_recent_source(req.source):
                self.logger.warning("Recent sources not updated: %r", str(req.source))
            self.refresh_files()
            self._store_a2l_cache(result.entry)
            self._replace_current_a2l(copied, result.entry[1])
            self._log_a2l_parse_summary(copied, self.current_a2l_data, result.parse_seconds)
            if self.current_file:
                self.current_file.a2l_path = copied
                self.current_file.a2l_data = self.current_a2l_data
            view_started = time.perf_counter()
            self._refresh_a2l_dependent_views()
            view_elapsed = time.perf_counter() - view_started
            if view_elapsed > self.slow_parse_warn_seconds:
                self.logger.warning(
                    "A2L view refresh was slow: path=%s elapsed_seconds=%.3f threshold_seconds=%.3f",
                    copied,
                    view_elapsed,
                    self.slow_parse_warn_seconds,
                )
            else:
                self.logger.info(
                    "A2L view refresh complete: path=%s elapsed_seconds=%.3f",
                    copied,
                    view_elapsed,
                )
            self.update_project_labels()
            self._rehome_focus_after_load()
            self._rehome_placeholder_focus_after_load()
            self.logger.info("A2L loaded: %s", copied)
            if req.sync_project and self.current_project:
                self._sync_loaded_a2l_to_project()
            self.call_after_refresh(
                self.end_busy,
                "a2l_load",
                gen,
                safe_text(f"A2L loaded: {painted_names([copied.name])}").plain,
            )
        except BaseException:
            self._busy_fail("a2l_load", gen)
            raise

    def _on_a2l_attach_failed(
        self, request: A2LAttachRequest, exc: BaseException
    ) -> None:
        """Main thread: the containment arm or the ``could not be read`` end."""
        if isinstance(exc, WorkareaContainmentError):
            self.logger.warning("A2L load rejected by workarea guard: %s", exc)
            self._quit_pending = False
            self.end_busy("a2l_load", request.gen, f"Cannot load A2L: {exc}")
            return
        if request.copy:
            self.refresh_files()
        self._quit_pending = False
        self.end_busy(
            "a2l_load",
            request.gen,
            f"File NOT loaded: '{painted_names([request.source.name])}' could not "
            "be read — check that the file can be opened, then load again.",
        )

    def _load_from_item(self, item: ListItem) -> None:
        """The ``#files_list`` pick: read ``item.data`` (the on-disk name)
        and load it exactly as the Workarea Files list's pick does (G1)."""
        filename = getattr(item, "data", None)
        if not filename:
            return
        self._load_workarea_file(filename)

    def _load_workarea_file(self, name: str) -> None:
        """
        Summary:
            Load one ``workarea/temp`` file by its on-disk name, in place
            (LLR-173.1b): the A2L arm keeps the 9a ``load_a2l_from_path``
            route (with its ``copy_into_workarea``, 256 MB cap and link
            re-check — A9b-05); the data arm loads with 0 copies.

        Args:
            name (str): The on-disk file name inside ``workarea/temp``.

        Returns:
            None

        Data Flow:
            - ``candidate = self.workarea / WORKAREA_TEMP / name``.
            - Before the question a vanish probe runs ``os.lstat`` and a
              deleted file loads nothing, silently (F-11 / 9b B88); an
              ``OSError`` there falls through to ``go`` (S12a-R2-1).
            - ``go`` re-checks the entry with one ``os.lstat`` immediately
              before the open (S-i, S12a-03): a non-regular file, a
              reparse point, or an over-cap size paints one refusal line
              and loads nothing (LLR-172.6b/.6c).
            - ``kind`` is ``attach`` for a MAC or A2L suffix (case-folded,
              LLR-174.4c), else ``image``; the seam runs before the load.

        Dependencies:
            Uses:
                - ``_confirm_then_load``
                - ``load_a2l_from_path`` / ``load_selected_file``
            Used by:
                - ``_load_from_item`` / ``_handle_load_dialog``
        """
        candidate = self.workarea / WORKAREA_TEMP / name
        try:
            deps.os.lstat(candidate)
        except FileNotFoundError:
            return
        except OSError:
            pass
        kind = (
            "attach"
            if candidate.suffix.lower() in (MAC_EXTENSIONS | A2L_EXTENSIONS)
            else "image"
        )

        def go() -> None:
            try:
                st = deps.os.lstat(candidate)
            except FileNotFoundError:
                return
            except OSError:
                st = None
            if (
                st is None
                or not stat.S_ISREG(st.st_mode)
                or deps._is_reparse_point(candidate)
            ):
                self.set_status(
                    safe_text(
                        f"File NOT loaded: '{painted_names([name])}' is not a "
                        "regular file — pick another file."
                    ).plain
                )
                self.logger.warning(
                    "Workarea pick refused (not a regular file): %r", name
                )
                return
            if st.st_size > workspace.DEFAULT_COPY_SIZE_CAP_BYTES:
                self.set_status(
                    safe_text(
                        f"File NOT loaded: '{painted_names([name])}' is too "
                        "large to open — load a smaller file."
                    ).plain
                )
                self.logger.warning(
                    "Workarea pick refused (too large): %r", name
                )
                return
            self.logger.info("Loading from workarea selection: %s", candidate)
            if candidate.suffix.lower() in A2L_EXTENSIONS:
                self.load_a2l_from_path(candidate, copy=False)
            else:
                gen = self._busy_begin_action("file_load", candidate.name)
                try:
                    self.step_busy("file_load", gen, 2)
                    self._start_load_worker(
                        candidate, gen=gen, sync_project=False
                    )
                except BaseException:
                    self._busy_fail("file_load", gen)
                    raise

        self._confirm_then_load(kind, name, go)

    def _load_mac_file(
        self,
        path: Path,
        a2l_path: Optional[Path] = None,
        a2l_data: Optional[dict] = None,
    ) -> LoadedFile:
        """
        Summary:
            Parse a ``.mac`` address map, attach optional A2L metadata, and build a
            ``LoadedFile`` suitable for the MAC viewer and hex panel. The A2L
            path/data are explicit arguments (LLR-177.1e: no session read, no
            cache write).

        Args:
            path (Path): Path to the ``.mac`` file (UTF-8 text).
            a2l_path (Optional[Path]): The already-resolved A2L path.
            a2l_data (Optional[dict]): The already-parsed A2L payload.

        Returns:
            LoadedFile: ``file_type`` ``mac``, sparse ``mem_map`` at parsed addresses,
            ``mac_records`` / ``mac_diagnostics`` from the parser, and merged A2L fields.

        Dependencies:
            Uses:
                - ``parse_mac_file``
                - ``build_row_bases``
            Used by:
                - ``_parse_data_file`` (MAC branch)
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
        self.logger.info(
            "Load phase boundary: mac_a2l_resolve_entry path=%s a2l_path=%s",
            path.name,
            a2l_path,
        )
        self._flush_logger()
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
        out: list[A2LCacheEntry] = []
        try:
            loaded = self._parse_loaded_file(path, a2l_files, a2l_cache_out=out)
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
        if out:
            self._store_a2l_cache(out[0])
        self._apply_loaded_file(loaded, path, load_started)

    def _parse_loaded_file(
        self,
        path: Path,
        a2l_files: Optional[list[Path]] = None,
        *,
        a2l_cache_out: Optional[list[A2LCacheEntry]] = None,
    ) -> Optional[LoadedFile]:
        """The session-reading wrapper of ``_parse_data_file`` (Q-h1).

        Summary:
            Resolve the A2L path/data from the file-load arguments or the
            session, parse through the explicit-input ``_parse_data_file``,
            and append the cache entry it used or made to ``a2l_cache_out``
            (never storing: Q-h1 — the caller stores on main). It keeps
            reading the session on the file-load worker (outside
            LLR-177.1e's three workers; finding F-6).

        Args:
            path (Path): File to parse.
            a2l_files (Optional[list[Path]]): A2L paths from project load.
            a2l_cache_out (Optional[list[A2LCacheEntry]]): The out-channel
                the entry is appended to.

        Returns:
            Optional[LoadedFile]: Parsed and merged payload.

        Dependencies:
            Uses: parse_a2l_cached / _a2l_cache_entry / _parse_data_file
            Used by: _start_load_worker / load_selected_file
        """
        suffix = path.suffix.lower()
        self.logger.info(
            "Loading file: path=%s suffix=%s project=%s",
            path,
            suffix,
            self.current_project,
        )
        a2l_path = a2l_files[0] if a2l_files else self.current_a2l_path
        if a2l_path is not None:
            entry = deps.parse_a2l_cached(a2l_path, self._a2l_cache_entry())
            a2l_data = entry[1]
            if a2l_cache_out is not None:
                a2l_cache_out.append(entry)
        else:
            a2l_data = self.current_a2l_data
        return self._parse_data_file(path, a2l_path, a2l_data, self.current_file)

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

    def _prepare_load_payload(
        self,
        loaded: LoadedFile,
        a2l_view_generation: Optional[int] = None,
        image_generation: Optional[int] = None,
    ) -> PreparedLoad:
        """
        Summary:
            Build every derived artifact the UI needs from a freshly parsed ``LoadedFile``,
            so the main thread only has to install them onto widgets.

        Args:
            loaded (LoadedFile): Parsed payload from ``_parse_loaded_file``.
            a2l_view_generation (Optional[int]): Predicted A2L attach generation
                for the upcoming apply — ``_start_load_worker`` passes the live
                counter + 1 when ``loaded.a2l_data`` exists, else the live
                counter (the apply seam only bumps when it installs a
                payload). This function must NOT read the mutable app
                counter itself off-thread; the default resolves the
                prediction on the calling thread for the synchronous
                shipped chain (batch-102 Inc 2, R-B102-A2L-006).
            image_generation (Optional[int]): Predicted image generation —
                the live counter + 1, ``_apply_prepared_load`` always bumps.
                Same threading contract as ``a2l_view_generation``.

        Returns:
            PreparedLoad: Bundle with MAC cache, validation report, highlights,
            out-of-range list, ``bases_set``, and A2L enrichment state plus the
            generation snapshot the A2L precompute was built against.

        Data Flow:
            - Pre-compute enriched A2L tags (or skip when no A2L present),
              keyed ``(a2l_view_generation, image_generation, mem_size)``
              — never ``id()``-based (F-B102-A2L-1).
            - Run ``_compute_mac_view_payload`` to produce the MAC table + validation output.
            - Derive MAC highlights and sorted out-of-range lists using the cached
              ``range_index``.
            - Freeze the ``row_bases`` into a ``frozenset`` so hex renders avoid rebuilding
              million-entry sets on every refresh.
            - Pack everything into a ``PreparedLoad`` with a matching ``mac_cache_key`` so
              ``update_mac_view`` treats the payload as a cache hit, and with the
              generation snapshots so the apply step can discard a stale precompute.

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
        # batch-102 Inc 2 (R-B102-A2L-006): resolve the generation
        # snapshot the precompute is built against. The worker passes
        # explicit predictions; the default mirrors that prediction on
        # the calling thread so the synchronous shipped chain
        # (parse -> prepare -> apply) keys the cache exactly as the
        # worker path does.
        if image_generation is None:
            image_generation = self._image_generation + 1
        if a2l_view_generation is None:
            a2l_view_generation = self._a2l_view_generation + (
                1 if loaded.a2l_data else 0
            )
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
            a2l_enriched_key = (
                a2l_view_generation,
                image_generation,
                len(mem_map) if mem_map is not None else -1,
            )
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
            a2l_view_generation=a2l_view_generation,
            a2l_image_generation=image_generation,
            mac_widths=mac_widths,
            mac_cell_rows=mac_cell_rows,
            mac_cell_styles=mac_cell_styles,
        )

    @work(thread=True, exclusive=True, group="load")
    def _start_load_worker(
        self,
        path: Path,
        a2l_files: Optional[list[Path]] = None,
        *,
        gen: int,
        sync_project: bool = True,
    ) -> None:
        """
        Summary:
            Off-thread worker that parses a file, precomputes every derived artifact,
            and schedules a single UI install on the Textual main thread.

        Args:
            path (Path): Already-copied workarea file to parse.
            a2l_files (Optional[list[Path]]): Optional A2L paths from project load.
            gen (int): The busy run's generation from ``_busy_begin_action``
                (keyword-only; Inc 12a S-m), passed to ``step_busy`` and the end.

        Returns:
            None

        Data Flow:
            - Log a ``worker_parse_start`` phase marker and run ``_parse_loaded_file``.
            - Log ``worker_parse_done`` then call ``_prepare_load_payload`` to build the
              MAC cache, validation report, highlights, out-of-range list, and bases set,
              passing the predicted post-apply generation snapshots (image +1; A2L +1
              only when the parse carried a payload) so the apply preflight can reject
              the whole bundle if either generation was superseded.
            - Dispatch ``_complete_prepared_load`` via ``call_from_thread`` so the UI
              wrapper owns installation, publication, optional sync and outcome.
            - On parse or prepare exceptions, fall back to installing the minimal
              non-precomputed payload (or surface the error when the parse itself failed).

        Dependencies:
            Uses:
                - ``_parse_loaded_file`` / ``_prepare_load_payload``
                - ``call_from_thread``
                - ``_complete_prepared_load`` / ``_handle_load_error``
            Used by:
                - ``load_from_path`` (load dialog and startup path)
        """
        try:
            load_started = time.perf_counter()
            self.logger.info(
                "Load phase boundary: worker_parse_start path=%s", path.name
            )
            self._flush_logger()
            out: list[A2LCacheEntry] = []
            try:
                loaded = self._parse_loaded_file(path, a2l_files, a2l_cache_out=out)
            except Exception as exc:
                self.call_from_thread(self._handle_load_error, path, exc, gen)
                return
            if loaded is None:
                suffix = path.suffix.lower()
                self.call_from_thread(
                    self._handle_load_error,
                    path,
                    ValueError(f"Unsupported file type: {suffix}"),
                    gen,
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
                # Predict the generations the apply step will have bumped by
                # installation: image +1 always, A2L +1 only with a payload.
                # A stale snapshot rejects the whole prepared load preflight.
                prepared = self._prepare_load_payload(
                    loaded,
                    a2l_view_generation=(
                        self._a2l_view_generation + 1
                        if loaded.a2l_data
                        else self._a2l_view_generation
                    ),
                    image_generation=self._image_generation + 1,
                )
            except Exception as exc:
                # Fall back to the slow-path install so users still see the file.
                self.logger.exception(
                    "Prepare load payload failed; falling back: %s", exc
                )
                prepared = PreparedLoad(loaded=loaded)
            if out:
                prepared.a2l_cache = out[0]
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
            self.call_from_thread(self.step_busy, "file_load", gen, 3)
            self.call_from_thread(
                self._complete_prepared_load,
                prepared,
                path,
                load_started,
                gen=gen,
                sync_project=sync_project,
            )
        except BaseException:
            self.call_from_thread(self._busy_fail, "file_load", gen)
            raise

    def _complete_prepared_load(
        self,
        prepared: PreparedLoad,
        path: Path,
        load_started: float,
        *,
        gen: int,
        sync_project: bool,
    ) -> None:
        """
        Summary:
            Complete one loose file load from its acceptance result, preserving
            project sync and success only for an installed fresh bundle.

        Args:
            prepared (PreparedLoad): Worker-prepared file and derived caches.
            path (Path): Original loaded path used for the success name.
            load_started (float): ``time.perf_counter`` value captured at start.
            gen (int): Busy generation for this file-load run.
            sync_project (bool): Whether an accepted load may sync its project.

        Returns:
            None

        Data Flow:
            - Apply and publish the prepared load on the UI thread.
            - On acceptance, retain optional project sync and defer ``Loaded``
              behind the detail-card barrier; sync disappearance fails the run.
            - On supersession, skip both and close immediately with kept-state text.

        Dependencies:
            Uses:
                - ``_apply_prepared_load`` / ``_sync_loaded_file_to_project``
                - ``end_busy``
            Used by:
                - ``_start_load_worker`` through ``call_from_thread``
        """
        accepted = self._apply_prepared_load(prepared, path, load_started)
        if not accepted:
            self.end_busy(
                "file_load", gen, "Load superseded — current state kept."
            )
            return
        if sync_project and self.current_project:
            try:
                self._sync_loaded_file_to_project()
            except FileNotFoundError:
                self._busy_fail("file_load", gen)
                return
        self.call_after_refresh(
            self.end_busy,
            "file_load",
            gen,
            f"Loaded {painted_names([path.name])}",
        )

    def _handle_load_error(self, path: Path, exc: Exception, gen: int) -> None:
        """
        Summary:
            UI-thread handler for load-worker failures: update status/progress and log.

        Args:
            path (Path): Source path that failed to load.
            exc (Exception): Exception raised during parsing.
            gen (int): The ``file_load`` run's generation (Inc 12a S-m).

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
        # E3 S12b-01 / S12b-R2-4: a failed load keeps the app running.
        self._quit_pending = False
        self.end_busy("file_load", gen, "Load failed")
