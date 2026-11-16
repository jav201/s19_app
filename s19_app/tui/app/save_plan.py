"""s19_app.tui.app.save_plan — S19TuiApp mixin: save_plan (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import stat
from typing import Optional, Sequence, Tuple
from ...utils import safe_text
from ..changes.io import serialize_change_document
from ..changes.model import DISPOSITION_APPLIED, DISPOSITION_BLOCKED
from ..models import ProjectVariantSet
from ..screens import SavePreview, SaveProjectPayload, SaveProjectScreen
from ..services.report_addendum import DeclaredRegion
from ..services.manifest_writer import serialize_manifest
from ..services.project_gather_service import (
    PLAN_ROLE_CARRIED,
    PLAN_ROLE_DOCUMENT,
    PLAN_ROLE_MANIFEST,
    PLAN_TARGET_MERGE,
    PLAN_TARGET_NEW,
    PLAN_TARGET_OPEN,
    PROJECT_PATCHES_DIR,
    PlannedFile,
    ProjectInventory,
    SavePlan,
    classify_active_document,
    document_home_for_kind,
    painted_names,
)
from ..services.variant_execution_service import (
    DOCUMENT_NEXT_STEP,
    DOCUMENT_REASON_IO_ERROR,
    PROJECT_MANIFEST_NAME,
    STEP_CHECK_THEN_LOAD,
    DerivedFrom,
    FileRecord,
    is_active_document_form,
    manifest_is_damaged,
    manifest_keep_reason,
)
from ..workspace import (
    _guarded_destination,
    A2L_EXTENSIONS,
    MAC_EXTENSIONS,
    PROJECT_DATA_EXTENSIONS,
    PROJECT_PRIMARY_DATA_EXTENSIONS,
    PROJECT_NAME_MAX_CHARS,
    RESERVED_WORKAREA_HOMES,
    WorkareaContainmentError,
    build_variant_set,
    is_windows_device_name,
    sanitize_project_name,
)
from . import deps
from .shared import (
    _ProjectImageStep,
    _SaveSession,
    _PreparedSave,
    DOCUMENT_MISSING,
    DOCUMENT_LINK,
    DOCUMENT_UNREADABLE,
    DOCUMENT_IO_ERROR,
    _DOCUMENT_IN_HOME,
)


#: The longest fixed in-project file name suffix (LLR-164.3): the
#: before/after report ``\reports\<ts>-NN-before-after-report.html`` costs
#: 53 characters beyond the project folder path.
_SAVE_REPORT_SUFFIX_CHARS = 53


def _save_manifest_keys(
    declared_regions: Sequence[DeclaredRegion],
    *,
    derived: bool = False,
    active_document: bool = False,
) -> tuple[str, ...]:
    """
    Summary:
        The ``project.json`` keys a Save project writes, read off the
        manifest writer itself (LED .45: the save plan takes them as an
        input), so the plan never carries a hand-copied key list.

    Args:
        declared_regions (Sequence[DeclaredRegion]): The regions the save
            writes; the writer adds ``declared_regions`` only when any exist.
        derived (bool): True when the save emits a patched image, which
            records ``derived_from`` (LLR-168.4).
        active_document (bool): True when the save records an
            ``active_document`` (LLR-167.6, LLR-170.1): the plan holds a
            document row the write records, or the save carries the
            target's value that Save project did not drop (LLR-164.2).

    Returns:
        tuple[str, ...]: The keys, in the writer's order. ``files`` is
            always among them (every save places at least one file and the
            seam records it, LLR-169.2). ``gathered`` is not: the gather
            decides it AFTER the plan (LED .63).

    Data Flow:
        - Serialize an empty composition with these regions, one ``files``
          record, for an emit one ``derived_from`` record and, for a
          recorded document, a placeholder ``active_document`` through
          ``serialize_manifest`` (no file is touched).
        - Parse the text back and keep its top-level key order.

    Dependencies:
        Uses:
            - manifest_writer.serialize_manifest
        Used by:
            - S19TuiApp._plan_project_save
    """
    digest = "0" * 64
    text, _issues = serialize_manifest(
        ProjectVariantSet(project_name="", variants=(), active_id=None),
        Path().resolve(),
        declared_regions=declared_regions,
        files={"image.s19": FileRecord(0, digest)},
        derived_from=(
            {"image.s19": DerivedFrom("base.s19", digest, 0)} if derived else None
        ),
        active_document=(
            f"{PROJECT_PATCHES_DIR}/changes.json" if active_document else None
        ),
    )
    return tuple(json.loads(text))


#: The save summary's kind words (LLR-175.4), one per ``PLAN_TARGET_*``
#: kind. The A11-17 fourth word ("new project in an existing folder") is
#: picked in ``_compose_save_preview`` because it keys on the folder's
#: content, not the kind alone.
_SAVE_KIND_WORDS: dict[str, str] = {
    PLAN_TARGET_NEW: "new folder",
    PLAN_TARGET_OPEN: "updates the open project",
    PLAN_TARGET_MERGE: "merges into an existing project",
}

#: The per-role labels of the painted plan rows (LLR-175.4, LLR-175.4g).
_SAVE_ROW_LABELS: dict[str, str] = {
    "image": "image",
    "mac": "MAC",
    "a2l": "A2L",
    PLAN_ROLE_DOCUMENT: "document",
    PLAN_ROLE_CARRIED: "file",
}

#: The refusal prefix every refusal the preparation returns starts with;
#: the dialog's where line is the status text minus this prefix (S-a).
_SAVE_REFUSAL_PREFIX = "Project NOT saved: "

#: The ``_plan_project_save`` sentinel: "no save-as source given; derive
#: it" (R2-08), so an explicit ``None`` keeps meaning "not a save as".
_UNSET = "no save-as source given; derive it"

#: A session-digest sentinel key recording that the file-backed change
#: document was already warned about this dialog open (S11-11), so a
#: multi-recompute preview logs one warning, not one per recompute. The
#: session's ``digests`` mapping is always the plain dict built by
#: ``_save_session_inputs``, so the marker survives the open.
_DOCUMENT_UNREADABLE_KEY = Path("<unreadable-change-document>")


def _unreadable_text(exc: OSError) -> str:
    """
    Summary:
        The one refusal text for an unreadable source or target file
        (LLR-175.1l, ruling Q11): names the file through ``painted_names``
        and appends the next step, so the dialog and the status line read
        the same scrubbed text. Shared by ``_save_session_inputs`` and
        ``_prepare_project_save``.

    Args:
        exc (OSError): The read error; ``filename`` may be ``None``.

    Returns:
        str: ``Project NOT saved: <name> could not be read: <reason> —
        check that the file can be opened, then save again. Nothing
        written.``

    Dependencies:
        Uses:
            - project_gather_service.painted_names
        Used by:
            - S19TuiApp._save_session_inputs / _prepare_project_save
    """
    name = (
        painted_names([Path(exc.filename).name])
        if exc.filename
        else "a source file"
    )
    return (
        f"Project NOT saved: {name} could not be read: {exc.strerror or exc} — "
        "check that the file can be opened, then save again. Nothing written."
    )
_PLACED_DOCUMENT_CLASSES = frozenset({_DOCUMENT_IN_HOME, "outside"})

#: The outcomes for which Save project drops a carried ``active_document``
#: (E3 R8 refined): a real file fault. ``too_large`` and ``io_error`` keep
#: the record.
_DOCUMENT_DROP_OUTCOMES = frozenset(
    {DOCUMENT_MISSING, DOCUMENT_LINK, DOCUMENT_UNREADABLE}
)

#: Why Save project dropped a carried ``active_document`` (E3 R2, R8
#: refined), in user terms.
_DOCUMENT_DROP_REASON: dict[str, str] = {
    DOCUMENT_MISSING: "the file is missing",
    DOCUMENT_LINK: "the file is a link",
    DOCUMENT_UNREADABLE: "the file is not a change or check document the app can read",
}


class SavePlanMixin:

    def action_save_project(self) -> None:
        """
        Summary:
            Open the Save project dialog (HLR-175f / LLR-175.3j). With
            nothing loaded it paints one status line and pushes no dialog
            (ruling Q9). Otherwise it pushes ``SaveProjectScreen`` with the
            keyword-only constructor — the ``preview`` / ``confirm``
            callables, the open project's on-disk name as ``initial_name``,
            and the unchanged per-variant assignment rows — and the session
            is computed lazily at the dialog's first ``preview``
            (LLR-175.5b).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Build ``variants`` via ``_variant_display_options`` and
              ``candidate_files`` via ``_assignment_candidate_files`` only
              when ``_variant_set``/``current_project_dir`` are present.
            - Drop any leftover per-open state, then push
              ``SaveProjectScreen`` with ``_handle_save_dialog`` as the
              dismiss callback (read at push time).

        Dependencies:
            Uses:
                - ``_variant_display_options`` / ``_assignment_candidate_files``
                - ``SaveProjectScreen`` / ``push_screen``
            Used by:
                - save-project keybinding / command palette entry
        """
        if self._refuse_if_busy():
            return
        if not self.current_file and not self.current_a2l_path:
            self.logger.info("Save project action triggered with no loaded files.")
            self.set_status("Nothing to save: load a data file or A2L first.")
            return
        if self.current_file:
            self.logger.info("Save project action triggered for %s", self.current_file.path)
        else:
            self.logger.info("Save project action triggered with A2L only.")
        variants: list[tuple[str, str]] = []
        candidate_files: list[str] = []
        variant_set = self._variant_set
        if variant_set is not None and variant_set.variants:
            variants = self._variant_display_options(variant_set)
            candidate_files = self._assignment_candidate_files()
        self._save_session = None
        self._save_confirmed = None
        self._save_painted_preview = None
        self.push_screen(
            SaveProjectScreen(
                preview=lambda name: self._save_dialog_preview(
                    name, self._current_save_session()
                ),
                confirm=self._confirm_project_save,
                initial_name=self.current_project,
                variants=variants,
                candidate_files=candidate_files,
            ),
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

    def _handle_save_dialog(self, payload: Optional[SaveProjectPayload]) -> None:
        """
        Summary:
            The Save dialog's one-argument dismiss router (HLR-175a,
            LLR-175.4l): drop the per-open state on every route out, then
            commit the confirmed prepared save when it matches the payload
            by plan-object identity (ruling Q-2), else prepare fresh and
            refuse or commit. A ``None`` payload cancels.

        Args:
            payload (Optional[SaveProjectPayload]): The dialog result, or
                ``None`` for a cancel.

        Returns:
            None

        Data Flow:
            - Clear ``_save_session`` / ``_save_confirmed`` /
              ``_save_painted_preview`` first (S-d).
            - G0-G3 (nothing loaded, parent checks) read the payload only.
            - Step 4: reuse ``confirmed`` only on the identity match, else
              ``_prepare_project_save`` (which computes the session lazily
              after the name rules when none was given, A11-09).
            - A refusal paints the status (and toasts on the direct path);
              otherwise ``_commit_project_save``.

        Dependencies:
            Uses:
                - _prepare_project_save / _commit_project_save
                - resolve_input_path
            Used by:
                - SaveProjectScreen dismiss (read at push time)
                - 56 direct call lines + 1 call by reference (tests)
        """
        session, confirmed = self._save_session, self._save_confirmed
        self._save_session = None
        self._save_confirmed = None
        self._save_painted_preview = None
        if payload is None:
            self.logger.info("Save project canceled.")
            return
        if not self.current_file and not self.current_a2l_path:
            self.set_status("Nothing to save: load a data file or A2L first.")
            self.logger.info("Save project dismissed: no loaded file or A2L.")
            return
        parent_resolved = deps.resolve_input_path(Path(payload.parent_folder), self.base_dir)
        if not parent_resolved or not parent_resolved.is_dir():
            self.set_status("Parent folder not found or not a directory.")
            self.logger.warning("Invalid parent folder: %s", payload.parent_folder)
            return
        # LLR-171.3 / LLR-171.3a: a project is saved only as a direct child
        # of THIS work area — equality of the real paths, never "below" it,
        # decided before any plan or folder exists.
        if deps.os.path.normcase(deps.os.path.realpath(parent_resolved)) != deps.os.path.normcase(
            deps.os.path.realpath(self.workarea)
        ):
            self.set_status(
                f"Project NOT saved: {parent_resolved} is not the work area "
                "folder — choose the work area as the parent folder "
                f"({self.workarea})."
            )
            self.logger.warning(
                "Save project refused: parent is not the work area: %r",
                str(parent_resolved),
            )
            return
        prepared = confirmed
        if not (
            confirmed is not None
            and payload.plan is not None
            and confirmed.plan is payload.plan
            and confirmed.typed_name == payload.project_name
            and session is not None
            and session.image_generation == self._image_generation
        ):
            prepared = self._prepare_project_save(payload.project_name, session)
        if prepared.refusal is not None:
            self.set_status(prepared.refusal)
            if prepared.toast:
                self.notify(
                    prepared.refusal,
                    title="Project not saved",
                    severity="error",
                    timeout=10.0,
                    markup=False,
                )
            self.logger.warning("Save project refused: %s", prepared.refusal)
            return
        self._commit_project_save(prepared, payload)

    def _prepare_project_save(
        self, name: str, session: Optional[_SaveSession] = None
    ) -> _PreparedSave:
        """
        Summary:
            The guard-and-plan half of a Save (LLR-175.6): every name rule,
            the source / target checks and the save plan, writing no file
            and no ``self.`` attribute except the declared lazy-inventory
            fill (S11-06). G4-G18 of the base ``_handle_save_dialog``, in
            order.

        Args:
            name (str): The typed project name.
            session (Optional[_SaveSession]): The per-open session; computed
                lazily after the name rules when ``None`` (A11-09).

        Returns:
            _PreparedSave: The prepared save (refusal, toast and plan among
                the fields).

        Data Flow:
            - G4-G10 the name rules; the work-area clash scan is wrapped in
              one ``try`` (S11-03).
            - G11 the session refusal (computed lazily here on the direct
              path); G12-G14 the target and save-as source checks.
            - G15 the plan (image step, carry, emitted record, the lazy
              save-as inventory, P-4's predicted active variant); G16-G18
              the OSError / plan / free-space refusals.

        Dependencies:
            Uses:
                - sanitize_project_name / is_windows_device_name
                - _save_session_inputs / _save_as_source_for /
                  _project_folder_refusal / _plan_project_save
                - _unreadable_text / _manifest_carry / _manifest_is_link
                - recorded_document_state / validate_project_files /
                  build_variant_set / inventory_project_tree
            Used by:
                - _handle_save_dialog / _save_dialog_preview /
                  _confirm_project_save
        """
        typed_name = name
        cleaned = ""
        project_dir = self.workarea
        save_as_source: Optional[Path] = None
        source_gone: Optional[str] = None
        # SE5-11-1: a session built before a load landed is rebuilt below,
        # so the plan never pairs one image's decision with another file.
        if session is not None and session.image_generation != self._image_generation:
            session = None

        def _refused(
            text: str, toast: bool = False, plan: Optional[SavePlan] = None
        ) -> _PreparedSave:
            return _PreparedSave(
                typed_name,
                cleaned,
                project_dir,
                save_as_source,
                source_gone,
                session.image_step if session is not None else _ProjectImageStep(emit=False),
                existing=None,
                target_carry={},
                carried_derived={},
                carried_active_document=None,
                carried_document_line=None,
                emitted_record=None,
                plan=plan,
                refusal=text,
                toast=toast,
            )

        # HLR-164: the name guards run BEFORE any folder is created, in the
        # contract's order — empty, device, reserved, the 64-character cap,
        # the full-path limit, the disguised clash, the link/junction target.
        # Every refusal paints its fixed token and a next step (UX-07).
        cleaned = sanitize_project_name(typed_name)
        if not cleaned:
            # A blank name, or one with no usable characters, is empty as a
            # project name (``sanitize_project_name`` strips first).
            return _refused(
                "Project NOT saved: name is empty — type a project name."
            )
        # LLR-164.1: Windows device names are refused on the RAW typed name,
        # on every path component of it and on the sanitised name — all
        # case-folded, so ``con.txt`` is refused rather than saved as
        # ``contxt``, and ``LPT¹`` names the same device as ``LPT1``.
        raw_components = [
            part
            for part in typed_name.replace("/", "\\").split("\\")
            if part
        ]
        if any(
            is_windows_device_name(part)
            for part in (typed_name, *raw_components, cleaned)
        ):
            return _refused(
                f"Project NOT saved: '{painted_names([typed_name])}' is a "
                "device name — choose another name."
            )
        reserved_folded = {home.casefold() for home in RESERVED_WORKAREA_HOMES}
        if cleaned.casefold() in reserved_folded:
            return _refused(
                f"Project NOT saved: '{cleaned}' is a reserved name — "
                "choose another name."
            )
        if len(cleaned) > PROJECT_NAME_MAX_CHARS:
            return _refused(
                "Project NOT saved: name too long "
                f"(at most {PROJECT_NAME_MAX_CHARS} characters) — "
                "shorten the name."
            )
        if (
            len(str(self.workarea)) + 1 + len(cleaned) + _SAVE_REPORT_SUFFIX_CHARS
            > deps._SAVE_FULL_PATH_LIMIT
        ):
            return _refused(
                "Project NOT saved: path too long — shorten the name."
            )
        # LLR-164.2 (Q-2): a project is a direct child of this work area
        # holding a ``project.json`` or a data file, not a reserved home and
        # not a link. A sanitised name equal to a project's folder name
        # case-folded is a disguised clash when the typed name differs from
        # that folder name — refused naming both, never suggesting a merge
        # (UX-35). The open project is exempt: its name typed exactly or as
        # its unsanitised form saves into it (LLR-164.2(c)); its on-disk
        # name typed in ANOTHER case saves into it under the on-disk
        # spelling (LED .52(a)) — while a case-only match against ANOTHER
        # project stays a clash.
        project_file_suffixes = PROJECT_DATA_EXTENSIONS | A2L_EXTENSIONS
        try:
            entries = sorted(self.workarea.iterdir())
        except OSError:
            return _refused(
                "Project NOT saved: the work area could not be read — check "
                "that the folder can be opened, then save again."
            )
        exact_folder = False
        open_spelling: Optional[str] = None
        for item in entries:
            if not item.is_dir():
                continue
            # F8: the cheap name comparison comes first — a non-matching
            # folder is never listed inside.
            if item.name.casefold() != cleaned.casefold():
                continue
            if item.name == cleaned:
                exact_folder = True
            if item.name.casefold() in reserved_folded:
                continue
            if deps._is_reparse_point(item):
                continue
            try:
                holds_project_file = (item / "project.json").is_file() or any(
                    child.is_file()
                    and child.suffix.lower() in project_file_suffixes
                    for child in item.iterdir()
                )
            except OSError:
                # SEC2-1: a folder that cannot be read is skipped, the
                # same as ``list_projects`` treats it — it never crashes
                # the save.
                continue
            if not holds_project_file:
                continue
            is_open_project = False
            if self.current_project_dir is not None:
                try:
                    is_open_project = deps.os.path.samefile(
                        item, self.current_project_dir
                    )
                except OSError:
                    is_open_project = False
            if is_open_project:
                # LED .52(a): adopt the on-disk spelling — the save
                # merges into the open project and ``current_project``
                # keeps the spelling its folder has.
                open_spelling = item.name
                continue
            if typed_name != item.name:
                return _refused(
                    f"Project NOT saved: '{painted_names([typed_name])}' is "
                    f"already a project as '{painted_names([item.name])}' — "
                    "choose another name."
                )
            # The exact name against a project that is not open: the save
            # merges — the files land as variants below (LLR-005.1); the
            # full merge carry arrives at Inc 8a.
        # LED .52(a) rebinds to the open project's on-disk spelling unless a
        # folder holds the exact typed name (seam ruling SR-11-1, B11-82:
        # `straße` typed with `strasse` open merges into `straße`).
        if open_spelling is not None and not exact_folder:
            cleaned = open_spelling
        # LLR-155.4: a source that vanished since the load (e.g. a same-name
        # save-back used to delete the work copy) refuses BEFORE the project
        # folder is created — no empty folder is left behind, the status
        # leads with the outcome (UX-C4) and the app keeps running.
        if session is None:
            session = self._save_session_inputs()
        if session.refusal is not None:
            return _refused(session.refusal, toast=True)
        # LED .50 / security finding SEC-1: the target stays UNRESOLVED —
        # the placement guard reads the work-area root off the textual path
        # (or the explicit root every app placement passes), so any junction
        # under the parent is seen instead of resolved away. LLR-171.3a: the
        # parent IS this work area, spelled as the app spells it, so the
        # save's spelling equals the load's.
        project_dir = self.workarea / cleaned
        # LLR-164.2 / HLR-164(f) / LLR-171.4g: a target that exists and is a
        # link or junction is refused BEFORE any resolve or write.
        target_reason = self._project_folder_refusal(project_dir)
        if target_reason == "link":
            return _refused(
                f"Project NOT saved: '{cleaned}' is a link or junction — "
                "choose another name."
            )
        if target_reason == "unreadable":
            return _refused(
                safe_text(
                    f"Project NOT saved: '{painted_names([cleaned])}' could not "
                    "be read — check that the folder can be opened, then save "
                    "again."
                ).plain
            )
        if target_reason is not None:
            return _refused(
                f"Project NOT saved: {project_dir.parent} is not the work area "
                "folder — choose the work area as the parent folder "
                f"({self.workarea})."
            )
        # LLR-171.1 / S3-6: a save as (a new target while a project is open)
        # checks the open project's folder ONCE, before any read of it; a
        # folder that became a link or left the work area refuses in the
        # plan and is never walked or read.
        save_as_source = self._save_as_source_for(project_dir)
        # LLR-171.1n (F1): the open project's folder is gone (renamed or
        # removed outside the app) — the save is a fresh-session save, as
        # at ebe6d0c, and one line names the missing folder.
        source_gone = (
            self.current_project_dir.name
            if save_as_source is None
            and self.current_project_dir is not None
            and not deps.os.path.lexists(project_dir)
            else None
        )
        source_reason = (
            self._project_folder_refusal(save_as_source)
            if save_as_source is not None
            else None
        )
        # HLR-167 / LLR-167.1 / LLR-167.6: decide the image on DATA and
        # compute the save plan BEFORE anything is created — a blocked
        # re-derive refuses the whole save and no folder is made.
        # LLR-164.4 / review F2: the plan reads every source it digests; a
        # source that cannot be read refuses here, before any folder
        # exists, and the app keeps running.
        active_variant: Optional[str] = None
        try:
            image_step = session.image_step
            # LLR-168.4 / LLR-167.6 (F3): the save's derived_from records —
            # the target's readable ones, carried, and the emitted image's
            # own — are decided HERE, once, so the plan lists exactly the
            # keys the save writes (an emit whose base cannot be read again
            # records none, and the plan shows none).
            existing = deps.read_project_manifest(project_dir)
            # LLR-171.1h: a save as carries the SOURCE project's records
            # (relative text, valid in the copy); a merge or an open-project
            # save carries the target's, as before. A source that failed
            # the folder check is never read (S3-6).
            if (
                save_as_source is not None
                and source_reason is None
                and not self._manifest_is_link(save_as_source)
            ):
                carry_dir: Path = save_as_source
                carry_manifest = deps.read_project_manifest(save_as_source)
            elif save_as_source is not None:
                carry_dir, carry_manifest = save_as_source, None
            else:
                carry_dir, carry_manifest = project_dir, existing
            target_carry = (
                self._manifest_carry(carry_dir, carry_manifest)
                if carry_manifest is not None and not manifest_is_damaged(carry_manifest)
                else {}
            )
            carried_derived: dict[str, DerivedFrom] = dict(
                target_carry.get("derived_from", {})
            )
            # LLR-164.2 / pre-ruling 7: a merge or an open-project save
            # carries the target's active_document. E3 R2 / R8 refined /
            # R10: the one document classifier drops it on a real file
            # fault and keeps it otherwise; its status line is painted in
            # the commit step, and only when the carried record is the one
            # written (E3 R15).
            carried_active_document: Optional[str] = target_carry.get(
                "active_document"
            )
            carried_document_line: Optional[str] = None
            if carried_active_document is not None:
                carried_state = deps.recorded_document_state(
                    carry_dir, carried_active_document
                )
                if carried_state.outcome in _DOCUMENT_DROP_OUTCOMES:
                    self.logger.warning(
                        "Save project drops the recorded change document: %s %s (%s)",
                        carried_active_document,
                        carried_state.outcome,
                        carried_state.detail,
                    )
                    carried_document_line = (
                        f"Change document record {carried_active_document} "
                        f"was dropped from {PROJECT_MANIFEST_NAME} — "
                        f"{_DOCUMENT_DROP_REASON[carried_state.outcome]}"
                    )
                    carried_active_document = None
                elif carried_state.outcome == DOCUMENT_IO_ERROR:
                    self.logger.warning(
                        "Save project could not read the recorded change "
                        "document: %s (%s)",
                        carried_active_document,
                        carried_state.detail,
                    )
                    carried_document_line = (
                        f"Change document {carried_active_document} "
                        f"{DOCUMENT_REASON_IO_ERROR} — it stays recorded; "
                        f"{DOCUMENT_NEXT_STEP[STEP_CHECK_THEN_LOAD]}"
                    )
            emitted_record = session.emitted_record
            if (
                save_as_source is not None
                and session.inventory is None
                and self.current_project_dir is not None
                and self._project_folder_refusal(self.current_project_dir) is None
            ):
                live = session is self._save_session
                inv = deps.inventory_project_tree(self.current_project_dir)
                session = replace(session, inventory=inv)
                if live:
                    self._save_session = session
            plan = self._plan_project_save(
                project_dir,
                cleaned,
                image_step,
                derived=bool(carried_derived) or emitted_record is not None,
                carried_active_document=carried_active_document,
                source_reason=source_reason,
                save_as_source=save_as_source,
                digests=session.digests,
                inventory=session.inventory if save_as_source is not None else None,
                payload_sha256=session.payload_sha256,
            )
            if plan.target_kind == PLAN_TARGET_MERGE:
                data_files, _a2l, _err = deps.validate_project_files(project_dir)
                if _err:
                    return _refused(
                        f"Project NOT saved: {_err}", toast=True, plan=plan
                    )
                image_row = next(
                    (row for row in plan.rows if row.role == "image"), None
                )
                if (
                    image_row is not None
                    and image_row.landing.suffix.lower()
                    in PROJECT_PRIMARY_DATA_EXTENSIONS
                ):
                    names = {p.name: p for p in data_files}
                    names[image_row.landing.name] = image_row.landing
                    vset = build_variant_set(cleaned, list(names.values()))
                    active_variant = next(
                        (
                            variant.variant_id
                            for variant in vset.variants
                            if variant.path.name == image_row.landing.name
                        ),
                        None,
                    )
        except OSError as exc:
            return _refused(_unreadable_text(exc), toast=True)
        if plan.refusal is not None:
            return _refused(plan.refusal, toast=True, plan=plan)
        # LLR-171.1e / R7: a save to a new folder needs the plan's total
        # (each file rounded up, plus the margin) in free space BEFORE the
        # folder exists; exactly the free space is enough.
        if plan.target_kind == PLAN_TARGET_NEW:
            try:
                free_bytes = shutil.disk_usage(self.workarea).free
            except OSError:
                return _refused(
                    "Project NOT saved: could not save — the free space of the "
                    "work area could not be read — check the folder."
                )
            if plan.total_bytes > free_bytes:
                return _refused(
                    f"Project NOT saved: not enough free space (needs "
                    f"{plan.total_bytes} bytes, {free_bytes} free) — free disk "
                    "space or remove files from the project.",
                    toast=True,
                )
        return _PreparedSave(
            typed_name,
            cleaned,
            project_dir,
            save_as_source,
            source_gone,
            image_step,
            existing,
            target_carry,
            carried_derived,
            carried_active_document,
            carried_document_line,
            emitted_record,
            plan,
            refusal=None,
            toast=False,
            active_variant=active_variant,
        )

    def _save_session_inputs(self) -> _SaveSession:
        """
        Summary:
            Compute Save project's per-open session (LLR-175.5, ruling Q-4):
            the image decision, the image/MAC/A2L digests, the emitted
            record and payload sha256 — everything that does not depend on
            the typed name. Opening and cancelling the dialog writes no
            file and no project state (A11-09).

        Returns:
            _SaveSession: The frozen session.

        Data Flow:
            - The missing-source test and the digest reads share one ``try``
              (S11-02), so an ``OSError`` there becomes the session refusal.
            - The image decision runs once per open; the emitted record
              (A11-01) and payload sha256 (S11-06) too.
            - The save-as inventory stays ``None`` here (filled lazily in
              ``_prepare_project_save``, S11-06); the file-backed document
              digest is recomputed per preparation (S11-05), not here.

        Dependencies:
            Uses:
                - _decide_project_image / _file_digest / _derived_record
                - _unreadable_text / painted_names
            Used by:
                - _current_save_session / _prepare_project_save (direct path)
        """
        generation = self._image_generation
        try:
            missing = [
                p
                for p in (
                    self.current_file.path if self.current_file else None,
                    self.current_file.mac_path if self.current_file else None,
                    self.current_a2l_path,
                )
                if p is not None and not p.exists()
            ]
            if missing:
                return _SaveSession(
                    _ProjectImageStep(emit=False),
                    {},
                    f"Project NOT saved: source file missing: "
                    f"{painted_names([missing[0].name])} — reload it or "
                    "remove it from the project.",
                    generation,
                )
            loaded = self.current_file
            image_step = (
                self._decide_project_image()
                if loaded
                else _ProjectImageStep(emit=False)
            )
            digests: dict[Path, Tuple[str, int]] = {}
            if loaded and not image_step.emit:
                digests[loaded.path] = deps._file_digest(loaded.path)
            if loaded and loaded.mac_path and loaded.mac_path != loaded.path:
                digests[loaded.mac_path] = deps._file_digest(loaded.mac_path)
            if self.current_a2l_path:
                digests[self.current_a2l_path] = deps._file_digest(self.current_a2l_path)
            emitted_record = (
                self._derived_record(self.current_file.path, image_step.derived)
                if image_step.emit and self.current_file is not None
                else None
            )
            payload_sha256 = (
                hashlib.sha256(image_step.payload).hexdigest()
                if image_step.emit
                else None
            )
        except OSError as exc:
            return _SaveSession(
                _ProjectImageStep(emit=False), {}, _unreadable_text(exc), generation
            )
        return _SaveSession(
            image_step,
            digests,
            image_step.refusal,
            generation,
            emitted_record=emitted_record,
            payload_sha256=payload_sha256,
        )

    def _current_save_session(self) -> _SaveSession:
        """The dialog's live session, computed on first use (LLR-175.5b) and
        again when a load landed since it was built (SE5-11-1)."""
        if (
            self._save_session is None
            or self._save_session.image_generation != self._image_generation
        ):
            self._save_session = self._save_session_inputs()
        return self._save_session

    def _save_dialog_preview(self, name: str, session: _SaveSession) -> SavePreview:
        """
        Summary:
            Compose the dialog's preview for the typed name (S-a / N3,
            LLR-175.1): blank text plans nothing (the empty pair arrives on
            Save via ``confirm("")``, Q-3), and a name-independent session
            refusal is shown even for an empty field.

        Args:
            name (str): The typed project name.
            session (_SaveSession): The per-open session.

        Returns:
            SavePreview: The preview, memoised as
                ``_save_painted_preview`` (A11-08).

        Dependencies:
            Uses:
                - _prepare_project_save / _compose_save_preview
            Used by:
                - SaveProjectScreen's ``preview`` callable
        """
        if not name.strip():
            where = (
                ((session.refusal.removeprefix(_SAVE_REFUSAL_PREFIX), "refusal"),)
                if session.refusal
                else ()
            )
            preview = SavePreview(where=where, rows=(), plan=None, refused=True)
        else:
            preview = self._compose_save_preview(
                self._prepare_project_save(name, session)
            )
        self._save_painted_preview = preview
        return preview

    def _compose_save_preview(self, prepared: _PreparedSave) -> SavePreview:
        """
        Summary:
            Compose the painted plain text of one prepared save (S-a,
            LLR-175.4): the where line, then the summary rows, every name
            through ``painted_names``, one line per row. A refusal paints
            its token pair and no rows (LLR-175.1i).

        Args:
            prepared (_PreparedSave): The guard-and-plan half's result.

        Returns:
            SavePreview: The composed preview.

        Dependencies:
            Uses:
                - painted_names / manifest_keep_reason / manifest_is_damaged
                - _folder_holds_project
            Used by:
                - _save_dialog_preview / _confirm_project_save
        """
        if prepared.refusal is not None:
            return SavePreview(
                where=(
                    (prepared.refusal.removeprefix(_SAVE_REFUSAL_PREFIX), "refusal"),
                ),
                rows=(),
                plan=prepared.plan,
                refused=True,
            )
        plan = prepared.plan
        root = Path(plan.target).resolve()

        def rel(path: Path) -> str:
            try:
                return path.relative_to(root).as_posix()
            except ValueError:
                return path.name

        kind = _SAVE_KIND_WORDS[plan.target_kind]
        if (
            plan.target_kind == PLAN_TARGET_MERGE
            and self._folder_holds_project(prepared.project_dir) is False
        ):
            kind = "new project in an existing folder"
        where = ((f"{painted_names([prepared.cleaned])} — {kind}", "info"),)
        rows: list[str] = []
        if prepared.source_gone is not None:
            rows.append(painted_names([prepared.source_gone]))
        if prepared.carried_document_line is not None:
            rows.append(painted_names([prepared.carried_document_line]))
        if plan.image:
            rows.append(plan.image)
        if (
            self.current_file
            and self._change_service.differs_from_last_saved(
                self.current_file.mem_map
            )
        ):
            rows.append(
                f"unsaved changes in "
                f"{painted_names([self.current_file.path.name])}"
            )
        for row in plan.rows:
            if row.role == PLAN_ROLE_MANIFEST:
                continue
            label = _SAVE_ROW_LABELS[row.role]
            if row.source is not None and row.source.name != row.landing.name:
                rows.append(
                    f"{label} {painted_names([row.source.name])} → "
                    f"{painted_names([rel(row.landing)])} — {row.action}"
                )
            else:
                rows.append(
                    f"{label} {painted_names([rel(row.landing)])} — {row.action}"
                )
        for folder in plan.folders:
            rows.append(
                f"folder {painted_names([folder.name])}/ "
                f"({folder.file_count} "
                f"{'file' if folder.file_count == 1 else 'files'}) — new"
            )
        if plan.skipped_links:
            rows.append(
                f"links or junctions not copied: {painted_names(plan.skipped_links)}"
            )
        if prepared.active_variant is not None:
            if (
                prepared.existing is not None
                and not manifest_is_damaged(prepared.existing)
                and prepared.existing.active_variant
            ):
                before = painted_names([prepared.existing.active_variant])
            else:
                before = "none recorded"
            rows.append(
                f"active variant {painted_names([prepared.active_variant])} "
                f"(before: {before})"
            )
        manifest_row = next(
            (row for row in plan.rows if row.role == PLAN_ROLE_MANIFEST), None
        )
        if manifest_row is not None:
            text = f"project.json — {manifest_row.action}"
            keep_reason = (
                manifest_keep_reason(prepared.existing)
                if prepared.existing is not None
                else None
            )
            if keep_reason is not None:
                text += (
                    f"; the current one {keep_reason}, a copy is kept as "
                    "project.json.previous-<UTC>"
                )
            rows.append(text)
        return SavePreview(where=where, rows=tuple(rows), plan=plan, refused=False)

    def _decide_project_image(self) -> _ProjectImageStep:
        """
        Summary:
            Save project's emit decision on data (LLR-167.1): re-derive the
            current CHANGE document onto a copy of the source image and emit
            iff the result differs from the source's data. A check document
            never counts. ``image_differs_from_source`` is only the fast
            path that starts the re-derive; it never decides copy. A blocked
            re-derive refuses the whole save (LLR-167.4).

        Returns:
            _ProjectImageStep: emit (with the re-derived copy, its summary,
                the emitted bytes and the entry counts), copy, or refuse.
                No image byte and no save record is written here (review
                F7); the document's collision findings (``document.issues``)
                are refreshed by the re-derive, as an apply does.

        Data Flow:
            - Fast path: a non-``change`` document, or one with no entry on
              an image the journal shows unchanged, copies at once.
            - Re-derive the document onto a copy of the session map; any
              blocked entry refuses the save, naming the addresses.
            - Compare the copy with the source's data over the document's
              spans: equal → copy (an applied-then-undone entry, or bytes
              the source already holds).
            - Differs → render the exact emitted bytes (an unsupported
              image kind refuses) and count the entries the image carries
              and how many of those no apply wrote before this save.

        Dependencies:
            Uses:
                - ChangeService.image_differs_from_source / rederive_for_save
                  / rederived_differs_from_source / save_entry_split
                - render_patched_image
                - _compute_a2l_enriched_tags
            Used by:
                - _handle_save_dialog (before the project folder exists)
        """
        loaded = self.current_file
        service = self._change_service
        document = service.document
        mem_map = loaded.mem_map
        if document.kind != "change" or not (
            service.image_differs_from_source(mem_map) or document.entries
        ):
            return _ProjectImageStep(emit=False)
        derived, summary = service.rederive_for_save(
            dict(mem_map),
            ranges=loaded.ranges,
            session_map=mem_map,
            mac_records=loaded.mac_records,
            a2l_tags=self._compute_a2l_enriched_tags() or None,
        )
        blocked = [
            record.address_start
            for record in summary.entries
            if record.disposition == DISPOSITION_BLOCKED
        ]
        if blocked:
            names = ", ".join(f"0x{address:08X}" for address in blocked)
            return _ProjectImageStep(
                emit=False,
                refusal=(
                    f"Project NOT saved: {len(blocked)} blocked "
                    f"{'entry' if len(blocked) == 1 else 'entries'} ({names}) "
                    "— fix them in the Patch Editor."
                ),
            )
        if not service.rederived_differs_from_source(mem_map, derived):
            return _ProjectImageStep(emit=False)
        payload = deps.render_patched_image(
            derived,
            loaded.ranges,
            source_kind=loaded.file_type,
            bytes_per_line=32,
            s0_header=loaded.source_s0_header,
        )
        if payload is None:
            return _ProjectImageStep(
                emit=False,
                refusal=(
                    f"Project NOT saved: a patched {loaded.file_type} image "
                    "cannot be written — only S19 and HEX images carry "
                    "change entries."
                ),
            )
        _applied, not_applied = service.save_entry_split()
        carried = {
            record.address_start
            for record in summary.entries
            if record.disposition == DISPOSITION_APPLIED
        }
        suffix = ".hex" if loaded.file_type == "hex" else ".s19"
        name = (
            loaded.path.name
            if loaded.path.suffix.lower() == suffix
            else loaded.path.stem + suffix
        )
        return _ProjectImageStep(
            emit=True,
            derived=derived,
            summary=summary,
            payload=payload,
            name=name,
            carried=len(carried),
            applied_by_save=sum(1 for address in not_applied if address in carried),
        )

    def _plan_project_save(
        self,
        project_dir: Path,
        project_name: str,
        image_step: _ProjectImageStep,
        derived: bool = False,
        carried_active_document: Optional[str] = None,
        source_reason: Optional[str] = None,
        *,
        save_as_source: Optional[Path] = _UNSET,
        digests: Optional[dict[Path, Tuple[str, int]]] = None,
        inventory: Optional[ProjectInventory] = None,
        payload_sha256: Optional[str] = None,
    ) -> SavePlan:
        """
        Summary:
            Build the one save plan (LLR-167.6, R-PC) from what this save
            will place: the image (the emitted bytes or the source), the MAC,
            the A2L and the Patch Editor's document, each with the digest
            the app computes here so the planner hashes nothing, plus the
            manifest keys (LED .45). For a save as (a new target while a
            project is open) it also passes the open project's link-free
            inventory, so the plan lists the files the copy places
            (LLR-171.1, LLR-167.6a); for an existing target, the names of
            its MAC / A2L files that are the open project's own (LLR-167.6f,
            pre-ruling 5).

        Args:
            project_dir (Path): The UNRESOLVED target folder.
            project_name (str): The target's on-disk name.
            image_step (_ProjectImageStep): The image decision.
            derived (bool): True when the save records ``derived_from``.
            carried_active_document (Optional[str]): The target's recorded
                ``active_document`` a merge or an open-project save carries,
                already dropped by the caller when the one document
                classifier said ``missing``, ``link`` or ``unreadable``
                (E3 R2, R8 refined); it sets the keys flag.
            source_reason (Optional[str]): The open project folder's
                ``_project_folder_refusal`` reason for a save as, checked
                once by the caller (S3-6); set -> the plan refuses (token
                row 9) and walks nothing.
            save_as_source (Optional[Path]): The save-as source, or
                ``_UNSET`` (the sentinel) to derive it from the open
                project (R2-08). A preparation call passes the value it
                computed once (R2-2 closed).
            digests (Optional[dict[Path, Tuple[str, int]]]): The
                session's image/MAC/A2L digests; ``None`` digests each
                source as today (the positional caller). A ``dict``: the
                S11-11 memo key is written into it.
            inventory (Optional[ProjectInventory]): The save-as inventory,
                computed lazily by the caller (P-1); ``None`` walks the
                source (as today). Read only for a save as.
            payload_sha256 (Optional[str]): The emitted payload's sha256,
                computed once per image generation (S11-06); ``None``
                hashes the payload here (the positional caller).

        Returns:
            SavePlan: The frozen plan the handler executes.

        Raises:
            OSError: A source the plan digests cannot be read, or the save
                as inventory cannot list the open project's folder (the
                caller refuses the save before any folder exists). The
                document's own digest never raises: it is "not placed"
                (A3R2-1).

        Data Flow:
            - The target kind first: ``new`` when nothing exists at the
              target, ``open project`` when the target is the open
              project's folder by file identity (S11-01), else ``merge``.
            - A ``new`` target with an open project: ``source_reason`` set
              -> the row 9 refusal (before the re-derive refusal, A3-13);
              else ``inventory_project_tree`` of the open project. Every
              other target passes no inventory (LLR-171.1g).
            - A save as from a MAC-only session (``file_type == "mac"``: a
              primary unload or a MAC-only load) drops the inventory's
              top-level S19 / HEX files, so no S19 / HEX file reaches the
              new project (R-WS-LOADED.19, Inc 10a E5 SE5-1).
            - The image row: the emitted bytes' digest (an emit) or the
              source file's (a copy); then the MAC and the A2L, each
              digested from its file. A refused decision plans no file.
            - The document row (LLR-170.2, A3-6), exactly when a file lands
              or is recorded: a pasted document (no ``source_path``) with at
              least 1 entry -> role ``document``, name ``changes.json`` in
              its kind's home, the digest of its serialized bytes. A
              file-backed document at any entry count (pre-ruling 8) ->
              ``classify_active_document`` (E3 R11): ``in_home`` /
              ``outside`` -> a row with the source file's digest (an
              ``OSError`` there -> no row); ``inside_elsewhere`` /
              ``missing`` -> no row.
            - An existing target: ``exempt`` holds each of its MAC / A2L
              names that is the open project's own — the same path as text,
              or the same name with the target file a regular file (never a
              link), the same size and the same SHA-256 as the session's
              file; only that file is hashed, here (no payload digests in
              the planner, Inc 5).
            - The manifest keys come from the manifest writer
              (``_save_manifest_keys``), with ``active_document`` when a
              document row's landing passes the form or a carried value
              remains.
            - A document copied or written into its home gets a row only
              when the home passes the guarded write's containment check
              (SEC8a-3, ``_document_home_contained``).

        Dependencies:
            Uses:
                - _file_digest / _save_manifest_keys
                - project_gather_service.classify_active_document /
                  document_home_for_kind / inventory_project_tree /
                  plan_project_save
                - changes.io.serialize_change_document
            Used by:
                - _handle_save_dialog (before the project folder exists)
        """
        if not deps.os.path.lexists(project_dir):
            target_kind = PLAN_TARGET_NEW
        else:
            is_open = False
            if self.current_project_dir is not None:
                try:
                    is_open = deps.os.path.samefile(
                        project_dir, self.current_project_dir
                    )
                except OSError:
                    is_open = False
            target_kind = PLAN_TARGET_OPEN if is_open else PLAN_TARGET_MERGE
        source_dir = (
            self._save_as_source_for(project_dir)
            if save_as_source is _UNSET
            else save_as_source
        )
        prepared_call = save_as_source is not _UNSET
        session_digests: dict[Path, Tuple[str, int]] = (
            digests if digests is not None else {}
        )
        refusal = image_step.refusal
        walked: Optional[ProjectInventory] = None
        if source_dir is not None and source_reason is not None:
            # Token row 9 (S3-6): first, with no walk and no re-derive text.
            where = {
                "link": "is a link or junction",
                "unreadable": "could not be read",
            }.get(source_reason, "is outside the work area")
            refusal = (
                f"Project NOT saved: the open project folder "
                f"'{painted_names([source_dir.name])}' {where} — pick a project "
                "in the list."
            )
        elif source_dir is not None and refusal is None:
            # CR11-F1: the caller's inventory is used only when this save is
            # a save as; any other target walks nothing (LLR-171.1g).
            walked = (
                inventory
                if inventory is not None
                else deps.inventory_project_tree(source_dir)
            )
        loaded = self.current_file
        if walked is not None and (
            loaded is None or loaded.file_type not in {"s19", "hex"}
        ):
            # Inc 10a (E5, SE5-1, RR-1; R-WS-LOADED.19): with no S19 / HEX
            # image loaded (a MAC spine, or nothing with or without an A2L),
            # a save as copies none of the open project's top-level S19 / HEX
            # files — after a primary unload one of them is the image the
            # operator unloaded.
            walked = replace(
                walked,
                top_level=tuple(
                    item
                    for item in walked.top_level
                    if deps.os.path.splitext(item.relative)[1].lower()
                    not in PROJECT_PRIMARY_DATA_EXTENSIONS
                ),
            )
        files: list[PlannedFile] = []
        image = ""

        def _digest(path: Path) -> Tuple[str, int]:
            if prepared_call and path in session_digests:
                return session_digests[path]
            return deps._file_digest(path)

        if loaded is not None and refusal is None:
            if image_step.emit:
                payload = image_step.payload
                files.append(
                    PlannedFile(
                        "image",
                        loaded.path,
                        image_step.name,
                        payload_sha256
                        if payload_sha256 is not None
                        else hashlib.sha256(payload).hexdigest(),
                        len(payload),
                    )
                )
                image = (
                    f"{painted_names([loaded.path.name])} + "
                    f"{image_step.carried} change "
                    f"{'entry' if image_step.carried == 1 else 'entries'}, "
                    f"{image_step.applied_by_save} applied by this save"
                )
            else:
                files.append(
                    PlannedFile(
                        "image", loaded.path, loaded.path.name,
                        *_digest(loaded.path),
                    )
                )
                image = f"{painted_names([loaded.path.name])} unchanged copy"
            if loaded.mac_path and loaded.mac_path != loaded.path:
                files.append(
                    PlannedFile(
                        "mac", loaded.mac_path, loaded.mac_path.name,
                        *_digest(loaded.mac_path),
                    )
                )
        if self.current_a2l_path and refusal is None:
            files.append(
                PlannedFile(
                    "a2l", self.current_a2l_path, self.current_a2l_path.name,
                    *_digest(self.current_a2l_path),
                )
            )
        records_document = False
        document = self._change_service.document
        home = document_home_for_kind(document.kind)
        source = document.source_path
        if refusal is None and source is None:
            if document.entries and self._document_home_contained(project_dir, home):
                data = serialize_change_document(document)
                name = "changes.json"
                files.append(
                    PlannedFile(
                        PLAN_ROLE_DOCUMENT, None, name,
                        hashlib.sha256(data).hexdigest(), len(data), home=home,
                    )
                )
                records_document = is_active_document_form(f"{home}/{name}")
        elif refusal is None:
            kind, name = classify_active_document(project_dir, source, home)
            if (
                kind in _PLACED_DOCUMENT_CLASSES
                and name is not None
                and (
                    kind == _DOCUMENT_IN_HOME
                    or self._document_home_contained(project_dir, home)
                )
            ):
                try:
                    digest, size = deps._file_digest(source)
                except OSError as exc:
                    if (
                        not prepared_call
                        or _DOCUMENT_UNREADABLE_KEY not in session_digests
                    ):
                        self.logger.warning(
                            "Save plan: change document not readable: %s (%s)",
                            source, type(exc).__name__,
                        )
                        if prepared_call:
                            # Cannot collide: real keys are absolute paths, and
                            # '<' '>' are not allowed in a Windows file name.
                            session_digests[_DOCUMENT_UNREADABLE_KEY] = (0, 0)
                else:
                    files.append(
                        PlannedFile(
                            PLAN_ROLE_DOCUMENT, source, name, digest, size, home=home
                        )
                    )
                    records_document = is_active_document_form(f"{home}/{name}")
        exempt: set[str] = set()
        if target_kind != PLAN_TARGET_NEW and refusal is None:
            target_data, target_a2l, _target_error = deps.validate_project_files(project_dir)
            planned_by_role = {planned.role: planned for planned in files}
            for item in (*target_data, *target_a2l):
                suffix = item.suffix.lower()
                if suffix in A2L_EXTENSIONS:
                    planned = planned_by_role.get("a2l")
                elif suffix in MAC_EXTENSIONS:
                    planned = planned_by_role.get("mac")
                else:
                    continue
                if planned is None:
                    continue
                try:
                    item_stat = deps.os.lstat(item)
                except OSError:
                    continue
                if not stat.S_ISREG(item_stat.st_mode) or deps._is_reparse_point(item):
                    continue
                if deps.os.path.normcase(deps.os.path.abspath(item)) == deps.os.path.normcase(
                    deps.os.path.abspath(planned.source)
                ):
                    exempt.add(item.name)
                    continue
                if (
                    deps.os.path.normcase(item.name) != deps.os.path.normcase(planned.name)
                    or item_stat.st_size != planned.size
                ):
                    continue
                try:
                    digest, _size = deps._file_digest(item)
                except OSError:
                    continue
                if digest == planned.digest:
                    exempt.add(item.name)
        return deps.plan_project_save(
            project_dir,
            target_kind=target_kind,
            files=files,
            image=image,
            manifest_keys=_save_manifest_keys(
                self._declared_regions,
                derived=derived,
                active_document=(
                    records_document or carried_active_document is not None
                ),
            ),
            refusal=refusal,
            inventory=walked,
            exempt=frozenset(exempt),
        )

    def _unrecorded_document_lines(
        self,
        project_dir: Path,
        source: Path,
        home: str,
        document_class: Optional[str],
        *,
        copied: bool,
        carried: Optional[str],
        carried_line: Optional[str],
    ) -> list[str]:
        """
        Summary:
            The one true status line about a file-backed change document
            this save does not record (E3 R3, review F2 / F3), or none when
            the carried record's own line already says it.

        Args:
            project_dir (Path): The target folder (unresolved).
            source (Path): The document's file.
            home (str): The home of its kind.
            document_class (Optional[str]): ``classify_active_document``'s
                class for ``source``.
            copied (bool): The gather copied it into ``home`` but did not
                name it (its name is outside the form).
            carried (Optional[str]): The carried ``active_document`` text
                that will be recorded, or ``None``.
            carried_line (Optional[str]): The carried record's own line.

        Returns:
            list[str]: Zero or one line.

        Data Flow:
            - The document IS the carried record (same project-relative
              text): no "not recorded" line; the carried line, when there
              is one, is the one line, else one line that the record stays
              as it was (F2).
            - Copied but not named, or already in ``home`` with a name
              outside the form: the name is the reason (F3).
            - Otherwise the class's reason.
        """
        absolute = Path(deps.os.path.abspath(source))
        try:
            text = absolute.relative_to(deps.os.path.abspath(project_dir)).as_posix()
        except ValueError:
            text = None
        in_home_folder = str(absolute.parent) == deps.os.path.join(
            deps.os.path.abspath(project_dir), home
        )
        name_reason = f"its name is not one {PROJECT_MANIFEST_NAME} records"
        if text is not None and text == carried:
            if carried_line is not None:
                return []
            where = (
                name_reason
                if in_home_folder
                else f"it is not in the project's {home} folder"
            )
            return [
                f"Change document {text} stays recorded in "
                f"{PROJECT_MANIFEST_NAME} as it was — {where}"
            ]
        if copied:
            return [
                f"Change document {source.name} was copied into the project's "
                f"{home} folder but is not recorded — {name_reason}"
            ]
        if document_class == "inside_elsewhere" and in_home_folder:
            reason = f"it is in the project's {home} folder, but {name_reason}"
        elif document_class == "inside_elsewhere":
            reason = f"it is in the project but not in its {home} folder"
        elif document_class == "missing":
            reason = "its file is missing or is a link"
        elif document_class == _DOCUMENT_IN_HOME:
            reason = "the file could not be read"
        else:
            reason = f"it could not be placed in the project's {home} folder"
        return [
            f"Change document {source.name} was not recorded in the project "
            f"— {reason}"
        ]

    def _document_home_contained(self, project_dir: Path, home: str) -> bool:
        """SEC8a-3: the guarded write's own containment check
        (``_guarded_destination`` with this app's work area, as
        ``place_into_workarea`` runs it) on the document's home, so the plan
        never promises a document row the write refuses."""
        try:
            _guarded_destination(project_dir / home, self.workarea)
        except (WorkareaContainmentError, OSError) as exc:
            self.logger.warning(
                "Save plan: change document home refused: %s (%s)",
                project_dir / home,
                type(exc).__name__,
            )
            return False
        return True

    def _save_as_source_for(self, project_dir: Path) -> Optional[Path]:
        """The open project's folder when Save project to ``project_dir`` is
        a save as (LLR-171.1): a target that does not exist while a project
        is open whose folder is still there. A folder that is gone is no
        source (LLR-171.1n, F1). Used by the handler and the plan alike."""
        if (
            self.current_project_dir is None
            or deps.os.path.lexists(project_dir)
            or not deps.os.path.lexists(self.current_project_dir)
        ):
            return None
        return self.current_project_dir
