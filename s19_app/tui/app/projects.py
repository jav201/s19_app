"""s19_app.tui.app.projects — S19TuiApp mixin: projects (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path, PurePosixPath
import stat
from typing import Callable, List, Mapping, Optional, Sequence
from ...core import S19File
from ...utils import safe_text
from ..models import LoadedFile, ProjectVariantSet
from ..operations import get_operation, list_operation_ids
from ..screens import OperationsScreen, SelectVariantScreen
from ..services.load_service import build_loaded_hex
from ..services.manifest_writer import MANIFEST_VERIFIED, derive_record
from ..services.project_gather_service import (
    PLAN_ACTION_KEEP,
    PLAN_ACTION_NEW,
    InventoryFile,
    SavePlanRow,
    painted_names,
)
from .. import workspace
from ..services.variant_execution_service import (
    PROJECT_MANIFEST_NAME,
    DerivedFrom,
    ProjectManifest,
    manifest_rewrite_refusal,
)
from ..workspace import (
    _guarded_destination,
    _path_traverses_reparse_point,
    A2L_EXTENSIONS,
    HEX_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    RESERVED_WORKAREA_HOMES,
    S19_EXTENSIONS,
    WorkareaContainmentError,
    build_variant_set,
    contained_in_workarea,
)
from . import deps
from .shared import (_TYPED_REFUSAL_TOKENS)
from .shared_io import (_plan_row_mismatch)


class ProjectsMixin:

    def _active_project_dir(self) -> Optional[Path]:
        """
        Summary:
            Return the absolute directory for the active saved project, if any.

        Args:
            None

        Returns:
            Optional[Path]: The project folder (as stored — see
            ``current_project_dir``, which LED .50 keeps UNRESOLVED so
            downstream placement guards see every junction), or ``None``
            when no project is active.

        Data Flow:
            - Prefer ``current_project_dir`` when set (external or explicit
              path — stored unresolved, under the work area).
            - Fall back to ``workarea / current_project`` for
              workarea-only projects.

        Dependencies:
            Used by:
                - A2L/data sync helpers
                - ``load_a2l_from_path`` project guard
        """
        if self.current_project_dir is not None:
            return self.current_project_dir
        if self.current_project:
            # LED .50 (review finding R3-2): app paths stay UNRESOLVED —
            # the placement guards take the root textually and resolve both
            # sides at the comparison point, so the fallback returns the
            # same unresolved spelling the Save/load write paths store
            # (``current_project_dir``, ``:8224`` / ``:8529``).
            return self.workarea / self.current_project
        return None

    def active_project_dir(self) -> Optional[Path]:
        """
        Summary:
            Public alias of :meth:`_active_project_dir` for non-app surfaces
            (change 1, HLR-138): the CRC Designer's save resolves its scoped
            template home through this seam — panels read public app
            accessors only, never the ``_``-prefixed internals.

        Args:
            None

        Returns:
            Optional[Path]: The active project's directory, or ``None``
            without a project — same value as :meth:`_active_project_dir`.

        Data Flow:
            - Pure delegation — one seam, two spellings, no second
              resolution logic to drift (C-14).

        Dependencies:
            Used by:
                - s19_app.tui.crc_designer_view.CrcDesignerPanel (Save)
        """
        return self._active_project_dir()

    def record_template_load(self, path: Path) -> None:
        """
        Summary:
            Record the CRC template path last successfully loaded through
            the CRC Designer (change 1, HLR-138): the save-gather's
            active-template limb copies the template the project USES into
            ``<project>/templates/`` at the next project save. The recorded
            path is the RESOLVED on-disk path (the same resolution the
            reader used), so the gather never re-resolves raw operator text.

        Args:
            path (Path): The resolved template file just loaded.

        Returns:
            None

        Data Flow:
            - Writes ``self._last_template_path`` — read by
              ``_handle_save_dialog`` at save time; a since-deleted path is
              tolerated there (one skip finding, never a crash).

        Dependencies:
            Used by:
                - s19_app.tui.crc_designer_view.CrcDesignerPanel (_load_template)
        """
        self._last_template_path = path

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
        if self._refuse_if_busy():
            return
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
            - The two refusal lines paint their name through
              ``painted_names`` (S10-04).
            - Stamp ``_pending_variant_id`` on the main thread inside the
              confirmed continuation, then dispatch ``load_from_path`` so
              parsing runs on the load worker thread and
              ``_apply_prepared_load`` installs + stamps on the main thread.

        Dependencies:
            Uses:
                - ``_confirm_then_load`` / ``load_from_path``
                - ``painted_names``
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
            self.set_status(f"Variant not found: {painted_names([variant_id])}")
            self.logger.warning("Variant not found in set: %s", variant_id)
            return
        if not descriptor.path.exists():
            self.set_status(
                f"Variant file missing: {painted_names([descriptor.path.name])}"
            )
            self.logger.warning("Variant file missing on disk: %s", descriptor.path)
            return

        def go() -> None:
            self.logger.info(
                "Activating variant '%s' via load pipeline: %s",
                variant_id,
                descriptor.path,
            )
            self._pending_variant_id = variant_id
            self.load_from_path(descriptor.path)

        self._confirm_then_load("image", descriptor.path.name, go)

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

    @property
    def _variant_set(self) -> Optional[ProjectVariantSet]:
        """The active project's variant set (LLR-005.5/005.6), or ``None``."""
        return self._variant_set_value

    @_variant_set.setter
    def _variant_set(self, value: Optional[ProjectVariantSet]) -> None:
        # batch-97 Inc-8 (PC-23): one setter for the four writers, so the key
        # bar's Select-variant token follows the set.
        self._variant_set_value = value
        self.refresh_bindings()

    def _parse_data_file(
        self,
        path: Path,
        a2l_path: Optional[Path],
        a2l_data: Optional[dict],
        existing: Optional[LoadedFile],
    ) -> Optional[LoadedFile]:
        """The explicit-input parse core (E1 A8): no session read (LLR-177.1e)."""
        suffix = path.suffix.lower()
        self.logger.info(
            "Load phase boundary: parse_branch_entry path=%s suffix=%s",
            path.name,
            suffix,
        )
        self._flush_logger()
        if suffix in S19_EXTENSIONS:
            s19 = S19File(str(path))
            loaded = deps.build_loaded_s19(path, s19, a2l_path, a2l_data)
            loaded = self._merge_primary_with_existing_mac(loaded, existing)
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
            hex_file = deps.IntelHexFile(str(path))
            loaded = build_loaded_hex(path, hex_file, a2l_path, a2l_data)
            loaded = self._merge_primary_with_existing_mac(loaded, existing)
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
            mac_loaded = self._load_mac_file(path, a2l_path, a2l_data)
            self.logger.info(
                "Load phase boundary: mac_merge_entry path=%s has_primary=%s",
                path.name,
                bool(existing and existing.file_type in {"s19", "hex"}),
            )
            self._flush_logger()
            loaded = self._merge_mac_with_existing_primary(mac_loaded, existing)
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

    def list_projects(self) -> List[str]:
        """
        Summary:
            The projects of this work area, in sorted order: each direct
            child folder that is not a reserved home, passes the one
            "is this folder a project here" check (LLR-171.4c) and holds
            project content (Q7 / LLR-173.4a) — a link or junction is never
            listed.

        Returns:
            List[str]: The project folder names, in ``iterdir`` sorted order.

        Data Flow:
            - The link check runs before ``is_dir()``, which follows a
              junction; a non-folder is skipped.
            - ``_folder_holds_project`` (the §1.3 content test) is the last
              step: ``False`` skips the folder, ``True`` or ``None`` (the
              content could not be read) lists it — a fail-open listing.
            - An ``OSError`` from ``iterdir`` propagates; each caller catches
              it (``_typed_load_route``, ``_handle_load_project``,
              ``_load_dialog_rows``).

        Dependencies:
            Uses:
                - _project_folder_refusal / _folder_holds_project
            Used by:
                - _load_dialog_rows / _typed_load_route / _handle_load_project
        """
        reserved_folded = {home.casefold() for home in RESERVED_WORKAREA_HOMES}
        projects = []
        for item in sorted(self.workarea.iterdir()):
            if item.name.casefold() in reserved_folded:
                continue
            # E3 R14 / LLR-172.4e: Win32 opens ``temp.`` / ``ab `` as
            # ``temp`` / ``ab``, so a name ending in a dot or a space would
            # load another folder; it is left out on every platform, as the
            # lister skips it (LLR-172.4d).
            if item.name.endswith((".", " ")):
                continue
            if self._project_folder_refusal(item) is not None:
                continue
            if not item.is_dir():
                continue
            # Q7 / LLR-173.4a: a folder that holds no ``project.json``, no
            # data file and no A2L file is not a listed project (§1.3). The
            # fail-open listing (``held is None``) keeps the typed route's
            # ``could not be read`` arm reachable (F-3, TC-B100-38).
            held = self._folder_holds_project(item)
            if held is False:
                continue
            projects.append(item.name)
        return projects

    def _listed_project_name(self, name: str) -> Optional[str]:
        """
        Summary:
            The one comparison of a name against the project list
            (LLR-172.5j, S-k): the on-disk spelling of the listed match, or
            ``None``. An exact listed name wins over a ``normcase`` match
            (SE5-12a-3: a case-sensitive folder can list ``Proj`` and
            ``proj``; picking ``proj`` opens ``proj``).

        Args:
            name (str): The typed or picked folder name.

        Returns:
            Optional[str]: The listed spelling, or ``None``.

        Raises:
            OSError: Propagates from ``list_projects``; each caller maps it.

        Dependencies:
            Uses: list_projects / os.path.normcase
            Used by: _handle_load_project / _typed_load_route
        """
        listed = self.list_projects()
        if name in listed:
            return name
        return next(
            (entry for entry in listed if deps.os.path.normcase(entry) == deps.os.path.normcase(name)),
            None,
        )

    @staticmethod
    def _manifest_is_link(folder: Path) -> bool:
        """SEC8b-3: True when ``folder/project.json`` is a link or reparse
        point (or cannot be inspected); a save as then carries nothing from
        it, and the inventory's link line names it."""
        manifest = folder / PROJECT_MANIFEST_NAME
        try:
            manifest_stat = deps.os.lstat(manifest)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return stat.S_ISLNK(manifest_stat.st_mode) or deps._is_reparse_point(manifest)

    def _project_folder_refusal(self, folder: Path) -> Optional[str]:
        """
        Summary:
            The one "is this folder a project here" check (HLR-171b), used
            by the project list, the project load, the Save project target
            and the save-as source: a reason word, or ``None``.

        Args:
            folder (Path): The folder, as the caller spells it (never
                resolved first).

        Returns:
            Optional[str]: ``"outside"`` when the folder is not one plain
                component of this work area or resolves outside it;
                ``"unreadable"`` when it cannot be inspected (F7(a));
                ``"link"`` when it is a symbolic link or a junction;
                ``None`` when it is a plain folder here or absent (absent
                is the caller's "not found" case).

        Data Flow:
            - (S3-7) ``folder.parent`` textually equal to the work area and
              a name other than "", "." or ".."; else ``"outside"``.
            - ``os.lstat``: absent -> ``None``; any other ``OSError`` ->
              ``"unreadable"`` (fail closed); a link or reparse point ->
              ``"link"``.
            - ``contained_in_workarea``: kept as defence; after the two
              steps above a plain direct child cannot resolve outside.

        Dependencies:
            Uses:
                - workspace._is_reparse_point / contained_in_workarea
            Used by:
                - list_projects / _handle_load_project / _handle_save_dialog
        """
        if str(folder.parent) != str(self.workarea) or folder.name in ("", ".", ".."):
            return "outside"
        try:
            folder_stat = deps.os.lstat(folder)
        except FileNotFoundError:
            return None
        except OSError:
            return "unreadable"
        if stat.S_ISLNK(folder_stat.st_mode) or deps._is_reparse_point(folder):
            return "link"
        if not contained_in_workarea(folder, self.workarea):
            return "outside"
        return None

    def _folder_holds_project(self, folder: Path) -> Optional[bool]:
        """
        Summary:
            The one §1.3 content test (Q7 / LLR-173.4a), shared by the
            project list, the pick match and the typed route (F-3): does
            this work-area folder hold a project?

        Args:
            folder (Path): A direct child folder of this work area.

        Returns:
            Optional[bool]: ``True`` when a regular ``project.json`` sits
            at the top or the folder holds a data, MAC or A2L file;
            ``False`` when it holds none of those; ``None`` when its
            content could not be read.

        Data Flow:
            - ``os.lstat(folder / PROJECT_MANIFEST_NAME)``: a regular file
              that is not a reparse point -> ``True``; any ``OSError``
              falls through to the listing, as the old step 11 did.
            - ``_list_project_files`` (link-safe, R2-N2): non-empty data or
              A2L -> ``True``; an ``OSError`` -> ``None``; else ``False``.
            - Reads metadata and at most one folder listing, writes
              nothing, and never raises an ``OSError``.

        Dependencies:
            Uses:
                - ``_list_project_files`` / ``_is_reparse_point``
                - ``PROJECT_MANIFEST_NAME``
            Used by:
                - ``list_projects`` / ``_typed_load_route``
        """
        manifest_path = folder / PROJECT_MANIFEST_NAME
        try:
            manifest_stat = deps.os.lstat(manifest_path)
        except OSError:
            manifest_stat = None
        if (
            manifest_stat is not None
            and stat.S_ISREG(manifest_stat.st_mode)
            and not deps._is_reparse_point(manifest_path)
        ):
            return True
        try:
            data_files, a2l_files, _error = self._list_project_files(folder)
        except OSError:
            return None
        if data_files or a2l_files:
            return True
        return False

    def _list_project_files(
        self, folder: Path
    ) -> tuple[list[Path], list[Path], Optional[str]]:
        """
        Summary:
            The one link-safe listing of a project folder (R2-N2,
            LLR-173.4n), shared by the preview and the install: one
            ``os.scandir`` with ``follow_symlinks=False`` collecting each
            regular file whose suffix is in ``PROJECT_DATA_EXTENSIONS``
            (which includes MAC) or ``A2L_EXTENSIONS``. A link, a directory
            or any other kind is skipped, so a linked ``.s19`` / ``.mac`` /
            ``.a2l`` is neither listed nor installed.

        Args:
            folder (Path): The project directory to scan.

        Returns:
            tuple[list[Path], list[Path], Optional[str]]:
                ``(data_files, a2l_files, error)`` — the 9a
                ``validate_project_files`` shape. ``data_files`` is sorted
                by ``(name.lower(), name)``; ``error`` is ``None`` or the
                9a "more than one MAC / A2L" refusal string (A9b-R3-4).

        Raises:
            OSError: Propagates to the caller's catch (``_folder_holds_project``
                -> ``None``, the preview -> ``could not be read``,
                ``_handle_load_project`` -> LLR-173.1g).

        Data Flow:
            - One ``os.scandir(folder)`` with ``follow_symlinks=False``.
            - ``entry.is_file(follow_symlinks=False)`` and not
              ``_is_reparse_point`` is the no-follow test (a symlink or any
              other reparse point is not a file); one ``lstat`` per entry,
              metadata only, writes nothing.

        Dependencies:
            Uses:
                - ``PROJECT_DATA_EXTENSIONS`` / ``MAC_EXTENSIONS`` /
                  ``A2L_EXTENSIONS`` / ``_is_reparse_point``
            Used by:
                - ``_folder_holds_project`` / ``_load_dialog_preview`` /
                  ``_handle_load_project``
        """
        data_files: list[Path] = []
        mac_files: list[Path] = []
        a2l_files: list[Path] = []
        with deps.os.scandir(folder) as entries:
            for entry in entries:
                item = Path(entry.path)
                # SEC9b-3: ``is_file(follow_symlinks=False)`` is False only for
                # a symlink; ``_is_reparse_point`` also catches every other
                # reparse point (a WSL link, a cloud placeholder).
                if not entry.is_file(follow_symlinks=False) or deps._is_reparse_point(item):
                    continue
                suffix = item.suffix.lower()
                if suffix in PROJECT_DATA_EXTENSIONS:
                    data_files.append(item)
                    if suffix in MAC_EXTENSIONS:
                        mac_files.append(item)
                elif suffix in A2L_EXTENSIONS:
                    a2l_files.append(item)
        data_files.sort(key=lambda item: (item.name.lower(), item.name))
        if len(mac_files) > 1:
            return data_files, a2l_files, "Project already has more than one MAC file."
        if len(a2l_files) > 1:
            return data_files, a2l_files, "Project already has more than one A2L file."
        return data_files, a2l_files, None

    def _a2l_admission(self, a2l_path: Path) -> Optional[str]:
        """
        Summary:
            The one A2L admission rule (A9b-R2-6), lifted from the 9a
            install arm so the preview and ``_handle_load_project`` share it
            (HLR-173a): the A2L the preview marks is exactly the A2L the
            install keeps.

        Args:
            a2l_path (Path): The A2L file to admit.

        Returns:
            Optional[str]: ``None`` when admissible (a regular file, not a
            reparse point, within ``DEFAULT_COPY_SIZE_CAP_BYTES``); else the
            9a reason string verbatim — ``is a link or junction``,
            ``is too large to open`` or ``could not be read`` (A9b-R3-2).

        Data Flow:
            - ``os.lstat``: an ``OSError`` -> ``could not be read``.
            - A non-regular file or a reparse point -> ``is a link or
              junction``; over the size cap (read at call time) ->
              ``is too large to open``.

        Dependencies:
            Uses:
                - ``_is_reparse_point`` / ``workspace.DEFAULT_COPY_SIZE_CAP_BYTES``
            Used by:
                - ``_load_dialog_preview`` / ``_handle_load_project``
        """
        try:
            a2l_stat = deps.os.lstat(a2l_path)
        except OSError:
            return "could not be read"
        if not stat.S_ISREG(a2l_stat.st_mode) or deps._is_reparse_point(a2l_path):
            return "is a link or junction"
        if a2l_stat.st_size > workspace.DEFAULT_COPY_SIZE_CAP_BYTES:
            return "is too large to open"
        return None

    def _copy_project_subfolders(
        self,
        source_dir: Path,
        project_dir: Path,
        copies: Sequence[InventoryFile],
        placed_files: list[Path],
        created_dirs: list[Path],
        carried: Optional[Mapping[str, SavePlanRow]] = None,
        *,
        workarea: Path,
        on_placed: Callable[[], None],
    ) -> Optional[str]:
        """
        Summary:
            Copy exactly the given entries of ``SavePlan.copies`` from the
            open project into the new one (LLR-171.1, pre-ruling 1): the
            files under the sub-folders right after the folder is created,
            and the top-level files after the rows loop (R11). It never
            walks the source, so it cannot descend into a link the plan
            skipped, and it writes nothing under ``source_dir``.

        Args:
            source_dir (Path): The open project's folder (unresolved).
            project_dir (Path): The new project's folder (unresolved).
            copies (Sequence[InventoryFile]): The plan entries to copy, in
                plan order.
            placed_files (list[Path]): The save's rollback list of files;
                each new landing is appended before the next copy.
            created_dirs (list[Path]): The save's rollback list of
                folders; each folder is appended the moment it exists.
            carried (Optional[Mapping[str, SavePlanRow]]): The plan's
                "carried" rows by landing name, for the top-level call.

        Returns:
            Optional[str]: ``None`` when every entry landed at its path;
                otherwise the failure line in user terms (token row 11, or
                the "the plan named" line for a carried row), the names
                through ``painted_names``. Exception text goes to the log
                only (R6).

        Data Flow:
            - Per entry: the source must still resolve inside the source
              project (A3-12), with no link or junction from the work
              area down to it (SEC8b-2); each missing folder level is checked by the
              guarded destination and then created (S3-5 b); the file goes
              through ``place_into_workarea`` with the destination
              unresolved; the source is checked again after the placement
              (S3-5 a).
            - A carried entry's landing is checked with
              ``_plan_row_mismatch`` (A3R2-5); any other entry must land at
              its own name.

        Dependencies:
            Uses:
                - workspace.place_into_workarea / _guarded_destination /
                  contained_in_workarea
                - project_gather_service.painted_names
            Used by:
                - _handle_save_dialog (twice for a save as)
        """
        def _source_in_place(source: Path) -> bool:
            # SEC8b-2: anchored on fixed ground — no folder from the work
            # area down to the file (P itself included) may be a link or
            # junction; the containment test alone moves with P.
            return not _path_traverses_reparse_point(
                source, stop_at=workarea
            ) and contained_in_workarea(source, source_dir)

        ensured: set[Path] = set()
        for entry in copies:
            parts = PurePosixPath(entry.relative).parts
            source = source_dir.joinpath(*parts)
            painted = painted_names([entry.relative])
            changed = (
                f"Project NOT saved: could not save — {painted} changed while "
                "saving — check the folder."
            )
            try:
                if not _source_in_place(source):
                    self.logger.warning(
                        "Save as copy refused: source left the project: %r",
                        entry.relative,
                    )
                    return changed
                level = project_dir
                for part in parts[:-1]:
                    level = level / part
                    if level in ensured:
                        continue
                    _guarded_destination(level.parent, workarea)
                    try:
                        level.mkdir()
                    except FileExistsError:
                        pass
                    else:
                        created_dirs.append(level)
                    ensured.add(level)
                placed = deps.place_into_workarea(
                    source, level, workarea_root=workarea
                )
                if not placed.reused:
                    placed_files.append(placed.path)
                on_placed()
                if not _source_in_place(source):
                    self.logger.warning(
                        "Save as copy refused: source changed during the copy: %r",
                        entry.relative,
                    )
                    return changed
            except (WorkareaContainmentError, OSError) as exc:
                self.logger.warning(
                    "Save as copy failed: %r (%s: %r)",
                    entry.relative, type(exc).__name__, str(exc),
                )
                return (
                    f"Project NOT saved: could not save — {painted} could not be "
                    "copied — check the folder."
                )
            row = carried.get(parts[-1]) if carried and len(parts) == 1 else None
            if row is not None:
                if _plan_row_mismatch(row, placed) is not None:
                    landed_action = PLAN_ACTION_KEEP if placed.reused else PLAN_ACTION_NEW
                    self.logger.warning(
                        "Save as plan mismatch: %r planned %r, landed %r",
                        entry.relative, str(row.landing), str(placed.path),
                    )
                    # F5: a reuse at another name repeats on every save —
                    # the copy holds a file with the same bytes already.
                    step = (
                        f"{painted_names([placed.path.name])} already holds the "
                        f"same bytes as {painted_names([parts[-1]])} — remove the "
                        "duplicate copy from the open project folder "
                        f"'{painted_names([source_dir.name])}', then save again."
                        if placed.reused
                        and deps.os.path.normcase(placed.path.name)
                        != deps.os.path.normcase(row.landing.name)
                        else "save again."
                    )
                    return (
                        "Project NOT saved: the plan named "
                        f"{painted_names([row.landing.name])} ({row.action}) but "
                        f"the file landed at {painted_names([placed.path.name])} "
                        f"({landed_action}) — {step}"
                    )
            elif deps.os.path.normcase(placed.path.name) != deps.os.path.normcase(parts[-1]):
                self.logger.warning(
                    "Save as copy landed elsewhere: %r at %r",
                    entry.relative, str(placed.path),
                )
                return (
                    f"Project NOT saved: could not save — {painted} did not land "
                    "at its path — check the folder."
                )
        return None

    def _manifest_carry(
        self, project_dir: Path, manifest: Optional[ProjectManifest]
    ) -> dict:
        """
        Summary:
            The ``project.json`` keys an in-project writer does not own
            (B100-I7, LLR-168.3), read back from disk and converted from the
            reader's absolute paths to project-relative POSIX strings — the
            only form ``serialize_manifest`` accepts (it refuses the whole
            manifest on one absolute entry, A-03).

        Args:
            project_dir (Path): The open project's folder.
            manifest (Optional[ProjectManifest]): That folder's manifest,
                read once by the caller; ``None`` when it has no
                ``project.json``.

        Returns:
            dict: ``batch``, ``assignments``, ``declared_regions``,
                ``gathered``, ``derived_from`` and ``active_document``
                keyword arguments for
                ``_write_and_verify_manifest``; empty when the project has
                no ``project.json``. ``files`` is not carried: the seam
                recomputes it from disk.

        Data Flow:
            - ``read_project_manifest`` resolves every entry against the
              resolved project folder; each is made relative to that same
              root. Entries the reader skipped (unsafe or malformed) are
              not carried — the serializer would refuse them.

        Dependencies:
            Used by:
                - ``_rewrite_project_manifest``
                - ``_handle_save_dialog`` (``derived_from``; a merge's
                  ``gathered``; a merge's or open-project save's
                  ``active_document``, LLR-164.2)
        """
        if manifest is None:
            return {}
        root = project_dir.resolve()

        def _relative(paths: Sequence[Path]) -> list[str]:
            return [path.relative_to(root).as_posix() for path in paths]

        return {
            "batch": _relative(manifest.batch),
            "assignments": {
                variant_id: _relative(paths)
                for variant_id, paths in manifest.assignments.items()
            },
            "declared_regions": manifest.declared_regions,
            "gathered": {
                home: _relative(paths) for home, paths in manifest.gathered.items()
            },
            "derived_from": {
                path.relative_to(root).as_posix(): record
                for path, record in manifest.derived_from.items()
            },
            # LLR-168.3 / LLR-164.2: already project-relative text as the
            # reader accepted it (``None`` when absent or refused). Carried
            # as recorded whether or not its file exists or reads —
            # dropping a faulty record is Save project's job (E3 R2, R8).
            "active_document": manifest.active_document,
        }

    def _rewrite_project_manifest(
        self,
        project_dir: Path,
        placed: Path,
        derived: Optional[DerivedFrom] = None,
    ) -> bool:
        """
        Summary:
            The one ``project.json`` rewrite of the in-project writers
            (LLR-168.3, the OQ-1 ruling): a readable manifest is rewritten
            through the seam with every key the writer does not own
            carried; a manifest it cannot carry whole — damaged, a newer
            ``schema_version``, unknown keys or skipped entries (SEC6-2) —
            is never rewritten.

        Args:
            project_dir (Path): The open project's folder.
            placed (Path): The file the writer just placed or saved there.
            derived (Optional[DerivedFrom]): The ``derived_from`` record of
                ``placed`` when the writer is a save-back (LLR-168.4).

        Returns:
            bool: True when ``project.json`` now records the session's
                state (written and verified); False when it was damaged and
                left as it is, the write failed, or the verify reported a
                mismatch.

        Data Flow:
            - The manifest is read once; the carry is built from that read.
            - No ``project.json`` -> one is written (OQ-1 (a)).
            - ``manifest_rewrite_refusal`` (damaged: over the size cap, not
              JSON, a top level that is not an object, an array over the
              entry cap; or SEC6-2: a ``schema_version`` other than 1,
              unknown top-level keys, skipped entries) -> no write: the
              placed file stays and one status line names the project, why
              and the file; the user's Save project stays the recovery
              (OQ-1 (b)). So a rewrite never drops what it cannot carry.
            - ``derived`` joins the carried ``derived_from`` records under
              the placed file's name.

        Dependencies:
            Uses:
                - read_project_manifest / manifest_rewrite_refusal
                - _manifest_carry / _write_and_verify_manifest
            Used by:
                - on_patch_editor_panel_save_back_decision
                - _sync_loaded_file_to_project (variant append, MAC sync)
                - _sync_loaded_a2l_to_project
        """
        manifest = deps.read_project_manifest(project_dir)
        refusal = manifest_rewrite_refusal(manifest) if manifest is not None else None
        if refusal is not None:
            project_name = self.current_project or project_dir.name
            self.set_status(
                safe_text(
                    f"{PROJECT_MANIFEST_NAME} in project '{project_name}' "
                    f"{refusal} and was not rewritten - {placed.name} stays in "
                    "the project; Save project rewrites it"
                ).plain
            )
            self.logger.warning(
                "Manifest not rewritten (%s): %s (placed %s)", refusal, project_dir, placed
            )
            return False
        carry = self._manifest_carry(project_dir, manifest)
        if derived is not None:
            carry["derived_from"] = {
                **carry.get("derived_from", {}),
                placed.name: derived,
            }
        if not self._write_and_verify_manifest(project_dir, **carry):
            return False
        result = self._last_manifest_verify_result
        return result is not None and result.status == MANIFEST_VERIFIED

    def _derived_record(
        self, base_path: Path, derived_map: Mapping[int, int]
    ) -> Optional[DerivedFrom]:
        """
        Summary:
            The ``derived_from`` record of an image this session just wrote
            (LLR-168.4): the base's file name and file digest, and how many
            bytes the written data differs from the base's data, computed
            while both are in hand.

        Args:
            base_path (Path): The base image file (the loaded image).
            derived_map (Mapping[int, int]): The written image's data.

        Returns:
            Optional[DerivedFrom]: The record; ``None`` when the base cannot
                be read again (logged) — the variant is then recorded
                without one, never with a guessed one.

        Dependencies:
            Uses:
                - manifest_writer.derive_record / _image_map
            Used by:
                - on_patch_editor_panel_save_back_decision
                - _handle_save_dialog (the emit)
        """
        try:
            return derive_record(base_path, deps._image_map(base_path), derived_map)
        except (OSError, ValueError, RuntimeError) as exc:
            self.logger.warning(
                "derived_from not recorded: base %s unreadable (%s)",
                base_path,
                type(exc).__name__,
            )
            return None

    def _activate_project_file(self, project_dir: Path, landed: Path) -> Optional[str]:
        """
        Summary:
            Make a file that just landed in the open project its active
            variant in the session (LLR-168.2 / LLR-168.3): rebuild the
            variant set from the folder, activate the landed file's variant
            and stamp it on the loaded image.

        Args:
            project_dir (Path): The open project's folder.
            landed (Path): The file the placement or the save landed on.

        Returns:
            Optional[str]: The activated variant id, or ``None`` when the
                folder does not validate (the variant set is left as it
                was).

        Data Flow:
            - The variant set is rebuilt from the folder, then the id is
              found by FILE NAME after the build: a stem collision makes the
              id the full file name (the E6 duplicate-id rule), so the stem
              is only the fallback.
            - The id becomes ``active_id`` and ``current_file.variant_id``;
              the project labels repaint. ``project.json`` is not touched
              here (the caller rewrites it).

        Dependencies:
            Uses:
                - ``validate_project_files`` / ``build_variant_set``
            Used by:
                - ``_sync_loaded_file_to_project`` (the variant append)
                - ``on_patch_editor_panel_save_back_decision``
        """
        data_files, _a2l_files, error = deps.validate_project_files(project_dir)
        if error is not None:
            self.logger.warning("Variant set not rebuilt during sync: %s", error)
            return None
        project_name = self.current_project or project_dir.name
        # Resolve the id AFTER the build by filename match — a stem
        # collision makes the id the full filename (E6 duplicate-id rule).
        self._variant_set = build_variant_set(project_name, data_files)
        variant_id = next(
            (
                variant.variant_id
                for variant in self._variant_set.variants
                if variant.path.name == landed.name
            ),
            landed.stem,
        )
        self._variant_set.active_id = variant_id
        if self.current_file is not None:
            self.current_file.variant_id = variant_id
        self.update_project_labels()
        return variant_id

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
              activation reload); otherwise place the file in through
              ``place_into_workarea``, rebuild the variant set with the new
              file active, stamp ``current_file.variant_id``, rewrite
              ``project.json`` through the seam with every key the append
              does not own carried, name the file Load now opens
              (LLR-168.3), and report the outcome in the status line — an
              added variant is reported as added; a reused file (identical
              bytes) names the existing variant instead (LLR-163.5).
            - MAC loads keep the pre-batch single-MAC sync rules; a MAC
              that lands rewrites ``project.json`` the same way (LLR-168.3).

        Dependencies:
            Uses:
                - ``validate_project_files`` / ``build_variant_set`` /
                  ``place_into_workarea`` (LLR-163.5)
                - ``update_project_labels`` / ``set_status``
            Used by:
                - ``_complete_prepared_load`` after an accepted prepared install
        """
        if not self.current_file:
            return
        project_dir = self._active_project_dir()
        if not project_dir:
            return
        try:  # SE5-12b-2: the open project's folder can vanish outside the app
            data_files, a2l_files, error = deps.validate_project_files(project_dir)
        except OSError:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"Project sync NOT done: project "
                    f"'{painted_names([self.current_project or project_dir.name])}' "
                    f"{reason} — {step}."
                ).plain
            )
            self.logger.warning(
                "Project sync refused (project folder could not be read): %r",
                project_dir,
            )
            return
        if error:
            self.logger.warning("Project validation failed during sync: %s", error)
            return
        if data_files:
            existing_suffixes = {item.suffix.lower() for item in data_files}
        else:
            existing_suffixes = set()
        mac_placed: Optional[Path] = None
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
                    # LLR-163.5: place through the one placement function; a
                    # reused file (byte-identical variant already in the
                    # project) names the EXISTING variant — never an
                    # added-variant status.
                    placement = deps.place_into_workarea(
                        self.current_file.path, project_dir,
                        workarea_root=self.workarea,
                    )
                    saved = placement.path
                    project_name = self.current_project or project_dir.name
                    appended_id = saved.stem
                    activated = self._activate_project_file(project_dir, saved)
                    if activated is not None:
                        appended_id = activated
                        # LLR-168.3: the appended file is the project's
                        # active variant on disk too; the status says which
                        # file Load now opens only once project.json
                        # records it (F2 / SEC6-4).
                        if self._rewrite_project_manifest(project_dir, saved):
                            self.set_status(
                                f"Project '{project_name}' now opens {saved.name}"
                            )
                    if placement.reused:
                        self.set_status(
                            f"Variant '{appended_id}' already in project "
                            f"'{project_name}'"
                        )
                        self.logger.info(
                            "Reused variant '%s' already in project: %s",
                            appended_id,
                            project_dir,
                        )
                    else:
                        self.set_status(
                            f"Added variant '{appended_id}' to project "
                            f"'{project_name}'"
                        )
                        self.logger.info(
                            "Appended variant '%s' into project: %s",
                            appended_id,
                            project_dir,
                        )
            elif self.current_file.path.suffix.lower() in MAC_EXTENSIONS and ".mac" not in existing_suffixes:
                mac_placed = deps.place_into_workarea(
                    self.current_file.path, project_dir,
                    workarea_root=self.workarea,
                ).path
                self.logger.info("Synced MAC data file into project: %s", project_dir)
            if (
                self.current_file.mac_path
                and self.current_file.mac_path != self.current_file.path
                and self.current_file.mac_path.suffix.lower() in MAC_EXTENSIONS
                and ".mac" not in existing_suffixes
            ):
                mac_placed = deps.place_into_workarea(
                    self.current_file.mac_path, project_dir,
                    workarea_root=self.workarea,
                ).path
                self.logger.info("Synced attached MAC file into project: %s", project_dir)
            if mac_placed is not None:
                # LLR-168.3: the MAC sync rewrites project.json, carrying
                # every key it does not own.
                self._rewrite_project_manifest(project_dir, mac_placed)
        except WorkareaContainmentError as exc:
            self.set_status(f"Project sync rejected: {exc}")
            self.logger.warning("Project sync rejected by workarea guard: %s", exc)

    def _sync_loaded_a2l_to_project(self) -> None:
        """Copy loaded A2L file into active project if allowed.

        The copy places through ``place_into_workarea`` and then rewrites
        ``project.json`` through ``_rewrite_project_manifest``, carrying
        every key the sync does not own (LLR-168.3).
        """
        if not self.current_a2l_path:
            return
        project_dir = self._active_project_dir()
        if not project_dir:
            return
        try:  # SE5-12b-2: the open project's folder can vanish outside the app
            data_files, a2l_files, error = deps.validate_project_files(project_dir)
        except OSError:
            reason, step = _TYPED_REFUSAL_TOKENS["unreadable"]
            self.set_status(
                safe_text(
                    f"A2L sync NOT done: project "
                    f"'{painted_names([self.current_project or project_dir.name])}' "
                    f"{reason} — {step}."
                ).plain
            )
            self.logger.warning(
                "A2L sync refused (project folder could not be read): %r",
                project_dir,
            )
            return
        if error:
            self.logger.warning("Project validation failed during A2L sync: %s", error)
            return
        if a2l_files:
            self.logger.info("Project already has A2L file, skipping sync: %s", project_dir)
            return
        try:
            placed = deps.place_into_workarea(
                self.current_a2l_path, project_dir, workarea_root=self.workarea
            ).path
            self.logger.info("Synced A2L file into project: %s", project_dir)
            self._rewrite_project_manifest(project_dir, placed)
        except WorkareaContainmentError as exc:
            self.set_status(f"A2L sync rejected: {exc}")
            self.logger.warning("A2L sync rejected by workarea guard: %s", exc)
