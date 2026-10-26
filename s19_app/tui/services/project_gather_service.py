"""Project gather (HLR-138) — the save-gather and the scoped artifact homes.

Change 1 of the operator's 2026-10-12 round (``prototypes/cambios_10_12_2026``):
the project folder becomes a self-contained snapshot. The shipped save
(``app.py`` ``_handle_save_dialog``) already COPYs the loaded S19/HEX + MAC +
A2L into the project dir; this module adds the JSON-artifact gather — the
change-set documents, the check documents, and the CRC templates the project
USES — into per-artifact project homes, leaving the COMMON originals
untouched (the COPY-not-MOVE ruling: the COMMON folders are live libraries the
app's dropdowns scan, so MOVE would silently empty them).

THE RECORDED PREDICATE (O-1, LLR-138.4's open item — recorded here, in code):

An artifact is "used by this project" — and therefore gathered — iff one of:

1. **Composition-referenced** — the change/check document is NAMED by the
   save's own composition: the project-wide ``batch`` list or any
   per-variant ``assignments`` value (the save payload, LLR-017). A
   project-relative name resolves first against the project dir (already
   home — nothing to gather), then against the COMMON
   ``workarea/patches/`` library by bare name (gathered).
2. **Active** — the change/check document loaded in the Patch Editor at
   save time (``ChangeService.document.source_path``) or the CRC template
   loaded in the CRC Designer at save time (the last successful
   ``_load_template`` path, recorded on the app as
   ``S19TuiApp._last_template_path``).
3. **Flow chains** — every flow under ``<project>/flows/`` is ALREADY
   project-only as shipped (``flow_persistence_service.FLOWS_SUBDIR``), so
   the flow limb of the gather is satisfied by construction: nothing to
   copy, and no COMMON flow home exists to leave untouched.

Classification into homes rides the v2 wire's own ``kind`` discriminator
(``"check"`` → ``checks/``, anything else → ``patches/``), so a check run
never lands in the change-set home and vice versa.

Snapshot semantics (LLR-138.4): every gather is a COPY stamped at save time.
A destination whose bytes already equal the source is skipped — the compare
runs against the requested name and every existing ``_<N>`` sibling the
placement produced, so an idempotent re-save stays duplicate-free even
after drifts (an unchanged re-save reuses the placed ``_<N>`` copy instead
of stacking another one); a destination that drifted from the source is
never overwritten in place — since Inc 3b (LLR-155.3, amended by
LED-2026-10-25-batch-99.7) the changed copy is placed through HLR-155's
placement (LLR-155.1/.2, :func:`copy_into_workarea`) and takes the next
free ``_<N>`` name, so a placed artifact is immutable once placed.
Divergence from later COMMON edits is accepted — the same semantics as the
shipped binaries copy-in.

Containment (the shipped law): every gathered byte resolves under
``<base>/.s19tool/workarea/`` — the destination re-runs ``copy_into_workarea``'s
own checks (workarea-root ancestry + reparse-point walk) before any byte is
written; an escape attempt is a per-artifact refusal finding
(collect-don't-abort), never an uncaught exception and never a partial write.

Headless by contract (mirroring ``manifest_writer``): stdlib + sibling-service
imports only, no ``textual`` symbol and no ``logging`` — the gather stays
reusable and testable without a running app. Change 2 (HLR-139, the
open-folder chips) reuses the same ruling through :func:`scoped_home_target`
(resolve-only) and :func:`scoped_home` (create-on-press) — one home-resolution
seam for both changes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    WorkareaContainmentError,
    _find_workarea_root,
    _path_traverses_reparse_point,
    copy_into_workarea,
)
from .variant_execution_service import MANIFEST_ARTIFACT

#: The per-artifact project homes (change 1, folders.html §1 — the drawn
#: tree names them ``patches\`` / ``checks\`` / ``templates\``).
PROJECT_PATCHES_DIR = "patches"
PROJECT_CHECKS_DIR = "checks"
PROJECT_TEMPLATES_DIR = "templates"

#: Project homes in their canonical census order (the ``gathered`` manifest
#: key serializes in this order).
PROJECT_HOME_NAMES: tuple[str, ...] = (
    PROJECT_PATCHES_DIR,
    PROJECT_CHECKS_DIR,
    PROJECT_TEMPLATES_DIR,
)

#: Gather finding — a used artifact resolved to no on-disk file (a dangling
#: composition reference or a since-deleted active path). A WARNING: the
#: gather is a best-effort snapshot, never a save blocker.
GATHER_SOURCE_MISSING = "GATHER-SOURCE-MISSING"

#: Gather finding — the project home failed the work-area containment checks
#: (no ``.s19tool/workarea/`` ancestry, or a reparse point in the chain), or
#: the copy itself raised ``OSError``. A WARNING (collect-don't-abort): the
#: save proceeds, the artifact simply is not gathered.
GATHER_CONTAINMENT = "GATHER-CONTAINMENT"

#: The manifest artifact tag every gather finding carries, so a gather
#: finding renders under the same artifact family as the manifest it rode in
#: with (MANIFEST_ARTIFACT is imported from the reader's module above).


def _gather_issue(
    code: str,
    message: str,
    severity: ValidationSeverity = ValidationSeverity.WARNING,
) -> ValidationIssue:
    """
    Summary:
        Build one gather finding tagged ``artifact=MANIFEST_ARTIFACT`` —
        the gather rides the save's manifest surfacing, so its findings name
        the same artifact family.

    Args:
        code (str): The finding code (``GATHER-SOURCE-MISSING`` /
            ``GATHER-CONTAINMENT``).
        message (str): Human-readable finding naming the artifact only.
        severity (ValidationSeverity): Defaults to WARNING (the gather is
            best-effort, never a save blocker).

    Returns:
        ValidationIssue: The finding.

    Data Flow:
        - Created only on a per-artifact skip path of
          :func:`gather_project_artifacts`.

    Dependencies:
        Used by:
            - gather_project_artifacts
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=MANIFEST_ARTIFACT,
    )


def document_home_for_kind(kind: str) -> str:
    """
    Summary:
        Map a change/check document's wire ``kind`` discriminator to its
        project home — ``"check"`` documents gather into ``checks/``
        (LLR-138.2), every other kind into ``patches/`` (LLR-138.1).

    Args:
        kind (str): The v2 wire ``kind`` token (``"change"`` / ``"check"``).

    Returns:
        str: :data:`PROJECT_CHECKS_DIR` when ``kind == "check"``;
            :data:`PROJECT_PATCHES_DIR` otherwise.

    Data Flow:
        - Pure token comparison — no IO, no parse.

    Dependencies:
        Used by:
            - gather_project_artifacts
            - s19_app.tui.app.S19TuiApp._change_doc_save_home
    """
    return PROJECT_CHECKS_DIR if kind == "check" else PROJECT_PATCHES_DIR


def read_document_kind(path: Path) -> str:
    """
    Summary:
        Read the v2 wire ``kind`` discriminator out of an on-disk
        change/check document — the gather's classification oracle for
        COMMON-library documents (the composition references a name, not a
        loaded document, so the kind is read from the wire).

    Args:
        path (Path): The document file to classify. Need not exist.

    Returns:
        str: The declared ``kind`` when the file is a well-formed JSON
            object carrying a string ``kind``; ``"change"`` otherwise (the
            change-set home is the default — an unreadable or foreign JSON
            is never silently dropped, and never raises).

    Data Flow:
        - ``json.load`` catching every parse/IO fault → ``"change"``.
        - No size cap re-check: the COMMON library entries already passed
          the reader's cap when they were written or loaded.

    Dependencies:
        Used by:
            - gather_project_artifacts
    """
    try:
        with path.open("rb") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, RecursionError):
        return "change"
    if isinstance(payload, dict) and isinstance(payload.get("kind"), str):
        return payload["kind"]
    return "change"


def _check_home_contained(home: Path) -> Path:
    """
    Summary:
        Re-run ``copy_into_workarea``'s containment CHECKS against a project
        home directory: locate its ``.s19tool/workarea`` root, confirm the
        resolved path stays inside it, and confirm no parent up to the
        workarea root traverses a symlink / NTFS junction — the exact checks
        the shipped copy seam runs before placing a file
        (``manifest_writer._check_destination_contained`` idiom, reused).

    Args:
        home (Path): The intended project home directory
            (``<project>/<home-name>/``).

    Returns:
        Path: The resolved home, when contained.

    Raises:
        WorkareaContainmentError: When the home has no
            ``.s19tool/workarea`` ancestor, escapes that root, or traverses
            a reparse point.

    Data Flow:
        - Resolve, then apply ``_find_workarea_root`` +
          ``is_relative_to`` + ``_path_traverses_reparse_point`` (the
          ``workspace.py`` containment seam).

    Dependencies:
        Uses:
            - _find_workarea_root / _path_traverses_reparse_point
        Used by:
            - _gather_copy
            - scoped_home
    """
    resolved = home.resolve()
    workarea_root = _find_workarea_root(resolved)
    if workarea_root is None or not resolved.is_relative_to(workarea_root):
        raise WorkareaContainmentError(
            "Refusing to gather: project home is not contained inside a "
            f".s19tool/workarea/ root: {resolved}"
        )
    if _path_traverses_reparse_point(resolved, stop_at=workarea_root.parent):
        raise WorkareaContainmentError(
            "Refusing to gather: project home traverses a symbolic link "
            f"or reparse point: {resolved}"
        )
    return resolved


def _same_artifact_name(source_name: str, candidate_name: str) -> bool:
    """
    Summary:
        The sibling-name shape one artifact's placements can take:
        ``<name>`` itself or a ``_<N>`` suffix of it (the house placement
        idiom) — ``hotfix.json``, ``hotfix_1.json``, … . Names that merely
        share the stem prefix (``hotfix_extra.json``) are a different
        artifact and never match.

    Args:
        source_name (str): The artifact's file name (e.g. ``hotfix.json``).
        candidate_name (str): A sibling candidate in the destination home.

    Returns:
        bool: ``True`` when ``candidate_name`` is ``<name>`` or one of its
            ``_<N>`` placements.

    Data Flow:
        - Pure string comparison — no IO, no parse.

    Dependencies:
        Used by:
            - _gather_copy
    """
    source = Path(source_name)
    candidate = Path(candidate_name)
    if candidate.suffix != source.suffix:
        return False
    if candidate.stem == source.stem:
        return True
    prefix = source.stem + "_"
    return candidate.stem.startswith(prefix) and candidate.stem[
        len(prefix):
    ].isdigit()


def _gather_copy(source: Path, home: Path) -> tuple[bool, Path]:
    """
    Summary:
        Copy one used artifact into its contained project home with the
        snapshot semantics (LLR-138.4): skip when a destination the
        placement could have produced — the requested name or an existing
        ``_<N>`` sibling — already holds the source's exact bytes (an
        idempotent re-save, after any number of drifts, adds no further
        ``_<N>`` duplicate); place a drifted source through HLR-155's
        placement (LLR-155.1/.2 via :func:`copy_into_workarea`) so it takes
        the next free ``_<N>`` name and the existing final name is never
        replaced or deleted (LLR-155.3 as amended by LED
        2026-10-25-batch-99.7); create the home on demand.

    Args:
        source (Path): The artifact's current on-disk path (the COMMON
            original or an arbitrary origin — the COPY ruling leaves the
            source untouched).
        home (Path): The destination project home directory. Must resolve
            under ``.s19tool/workarea/``.

    Returns:
        tuple[bool, Path]: ``(copied, destination)`` — ``copied`` is
            ``False`` when a matching sibling already held the source's
            bytes (skipped), ``True`` when bytes were placed;
            ``destination`` is the resolved target file either way — the
            sibling that held the bytes on a skip (the requested name or an
            ``_<N>`` placement), the next free ``_<N>`` name on drift.

    Raises:
        WorkareaContainmentError: When ``home`` fails the containment
            checks (the escape-refusal limb) or the placement refuses.
        OSError: When the read/compare fails mid-copy.
        FileNotFoundError: When ``source`` does not exist.

    Data Flow:
        - ``_check_home_contained(home)`` first — no byte moves before the
          containment verdict.
        - Byte-compare against the requested name and every ``_<N>``
          sibling; on drift, ``copy_into_workarea`` stages privately and
          claims the next free name — never an ``unlink``/recopy onto the
          existing final name.

    Dependencies:
        Uses:
            - _check_home_contained
            - _same_artifact_name (the sibling scan)
            - copy_into_workarea (the placement, LLR-155.1/.2)
        Used by:
            - gather_project_artifacts
    """
    resolved_home = _check_home_contained(home)
    source_bytes = source.read_bytes()
    destination = resolved_home / source.name
    # LLR-138.4 (review finding F1): the byte-compare must run against
    # EVERY name the placement could have produced — ``<name>`` and each
    # ``_<N>`` — not only the requested name. After one drift the current
    # bytes live at ``_<N>``; comparing only ``<name>`` would place a fresh
    # ``_<N+1>`` on every unchanged re-save.
    if resolved_home.is_dir():
        for sibling in sorted(resolved_home.iterdir()):
            if sibling.is_symlink() or not _same_artifact_name(
                source.name, sibling.name
            ):
                continue  # a symlinked or foreign name is not a placement
            # this artifact produced — never trusted as a reuse target
            try:
                if sibling.is_file() and sibling.read_bytes() == source_bytes:
                    return False, sibling
            except OSError:
                continue  # an unreadable sibling is not trusted, so the
                # scan keeps looking and the placement takes the next
                # free name
    placed = copy_into_workarea(source, resolved_home)
    return True, placed


@dataclass(slots=True)
class GatherOutcome:
    """
    Summary:
        The gather's result — the ``gathered`` manifest rows (project home
        → sorted project-relative POSIX paths, canonical
        :data:`PROJECT_HOME_NAMES` order, empty homes omitted) plus every
        per-artifact finding (collect-don't-abort).

    Args:
        gathered (dict[str, list[str]]): Home name → project-relative
            paths of the artifacts now held in that home.
        issues (list[ValidationIssue]): Every skip/refusal finding — empty
            on a fully-clean gather.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`gather_project_artifacts`.
        - Consumed by ``S19TuiApp._handle_save_dialog``, which threads
          ``gathered`` into the manifest write (``manifest_writer``).

    Dependencies:
        Used by:
            - s19_app.tui.app.S19TuiApp._handle_save_dialog
    """

    gathered: dict[str, list[str]] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)


def gather_project_artifacts(
    project_dir: Path,
    *,
    composition_names: Sequence[str] = (),
    active_document: Optional[Path] = None,
    active_document_kind: str = "change",
    active_template: Optional[Path] = None,
    common_patches_dir: Path,
    common_templates_dir: Path,
) -> GatherOutcome:
    """
    Summary:
        Gather every artifact the project USES — per the predicate recorded
        in this module's docstring (O-1) — into its per-artifact project
        home (HLR-138 / LLR-138.1..138.3). Change/check documents named by
        the save composition or active in the Patch Editor COPY into
        ``patches/`` or ``checks/`` per the wire ``kind``; the template
        active in the CRC Designer COPYs into ``templates/``; flow chains
        are already project-only and contribute nothing. The COMMON
        originals are never moved, deleted, or modified (the COPY ruling).

    Args:
        project_dir (Path): The just-saved project directory — the gather
            root. Must live under ``.s19tool/workarea/`` (the shipped save
            path guarantees it; an escape is a refusal finding, not a
            crash).
        composition_names (Sequence[str]): The save payload's ``batch`` +
            ``assignments`` document names (project-relative strings).
        active_document (Optional[Path]): The Patch Editor's loaded
            document path, when one is loaded.
        active_document_kind (str): That document's wire ``kind`` (the
            in-memory discriminator — the file itself is the source).
        active_template (Optional[Path]): The CRC Designer's last
            successfully loaded template path, when one was loaded.
        common_patches_dir (Path): The COMMON change/check library
            (``<base>/.s19tool/workarea/patches/``) — the composition
            fallback resolution root.
        common_templates_dir (Path): The COMMON CRC template library
            (``<base>/.s19tool/templates/``).

    Returns:
        GatherOutcome: The ``gathered`` manifest rows + collected
        per-artifact findings. Zero used artifacts → empty ``gathered`` +
        empty ``issues`` — the empty save is never an error (QC-3
        boundary catalog).

    Raises:
        None: Every failure mode is a collected finding
            (collect-don't-abort, C-5) — a refused or missing artifact
            never blocks the save.

    Data Flow:
        - Build the used set: composition names (project-dir hit → already
          home; COMMON hit by bare name → gather; neither → one
          ``GATHER-SOURCE-MISSING`` finding) + the active document (when
          its resolved path is not already inside the project dir) + the
          active template.
        - De-duplicate by resolved source path so a document both
          referenced and active is gathered once.
        - Each artifact COPYs through :func:`_gather_copy` into its home;
          successes append the project-relative POSIX path to
          ``gathered[home]`` (sorted per home, canonical home order).

    Dependencies:
        Uses:
            - document_home_for_kind / read_document_kind
            - _gather_copy
        Used by:
            - s19_app.tui.app.S19TuiApp._handle_save_dialog

    Example:
        >>> outcome = gather_project_artifacts(  # doctest: +SKIP
        ...     project_dir, composition_names=["boost.json"],
        ...     common_patches_dir=workarea / "patches",
        ...     common_templates_dir=base / ".s19tool" / "templates",
        ... )
    """
    outcome = GatherOutcome()
    resolved_project = project_dir.resolve()
    pending: dict[Path, str] = {}  # resolved source → home name

    def _schedule(source: Path, home: str) -> None:
        try:
            resolved_source = source.resolve()
        except OSError:
            resolved_source = source
        if resolved_source in pending:
            return
        pending[resolved_source] = home

    # Predicate limb 1 — the save's own composition.
    for name in composition_names:
        in_project = (resolved_project / name).resolve()
        if in_project.is_file():
            continue  # already home — the manifest batch/assignments carry it
        common_candidate = common_patches_dir / Path(name).name
        if common_candidate.is_file():
            _schedule(common_candidate, document_home_for_kind(read_document_kind(common_candidate)))
        else:
            outcome.issues.append(
                _gather_issue(
                    GATHER_SOURCE_MISSING,
                    f"gather: composition document {name!r} resolved to no "
                    f"file in the project or the common patches library — skipped",
                )
            )

    # Predicate limb 2a — the active editor document.
    if active_document is not None:
        try:
            resolved_active = active_document.resolve()
        except OSError:
            resolved_active = active_document
        if not resolved_active.is_relative_to(resolved_project):
            if resolved_active.is_file():
                _schedule(
                    resolved_active,
                    document_home_for_kind(active_document_kind),
                )
            else:
                outcome.issues.append(
                    _gather_issue(
                        GATHER_SOURCE_MISSING,
                        f"gather: active document {active_document} no "
                        f"longer exists — skipped",
                    )
                )

    # Predicate limb 2b — the active CRC template.
    if active_template is not None:
        try:
            resolved_template = active_template.resolve()
        except OSError:
            resolved_template = active_template
        if not resolved_template.is_relative_to(resolved_project):
            if resolved_template.is_file():
                _schedule(resolved_template, PROJECT_TEMPLATES_DIR)
            else:
                outcome.issues.append(
                    _gather_issue(
                        GATHER_SOURCE_MISSING,
                        f"gather: active template {active_template} no "
                        f"longer exists — skipped",
                    )
                )

    gathered_rows: dict[str, list[str]] = {}
    for resolved_source, home in sorted(pending.items(), key=lambda item: str(item[0])):
        try:
            _copied, destination = _gather_copy(resolved_source, resolved_project / home)
        except (WorkareaContainmentError, OSError) as exc:
            outcome.issues.append(
                _gather_issue(
                    GATHER_CONTAINMENT,
                    f"gather: refused to copy {resolved_source} into "
                    f"{resolved_project / home}: "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            continue
        relative = destination.relative_to(resolved_project).as_posix()
        gathered_rows.setdefault(home, []).append(relative)
    outcome.gathered = {
        home: sorted(rows)
        for home, rows in sorted(
            gathered_rows.items(),
            key=lambda item: PROJECT_HOME_NAMES.index(item[0]),
        )
    }
    return outcome


def scoped_home(
    project_dir: Optional[Path],
    subdir: str,
    common_home: Path,
) -> Path:
    """
    Summary:
        Resolve the change-1 scoped artifact home (the second half of
        HLR-138): with a project, NEW artifacts default INTO the project
        dir under ``subdir`` (created on demand, containment-checked); with
        NO project they keep the COMMON home. The Patch Editor save
        (``patches/`` / ``checks/`` by document kind) and the CRC Designer
        save (``templates/``) both resolve through this one seam so the
        project-vs-COMMON ruling lives in exactly one place.

    Args:
        project_dir (Optional[Path]): The active project's directory, or
            ``None`` without a project.
        subdir (str): The per-artifact project subfolder
            (:data:`PROJECT_PATCHES_DIR` / :data:`PROJECT_CHECKS_DIR` /
            :data:`PROJECT_TEMPLATES_DIR`).
        common_home (Path): The COMMON home kept when no project is
            active.

    Returns:
        Path: The (now-existing) home directory.

    Raises:
        WorkareaContainmentError: When a PROJECT home escapes the
            ``.s19tool/workarea/`` containment root (the shipped law holds
            for the scoped homes exactly as for the gather).

    Data Flow:
        - ``project_dir`` present → ``_check_home_contained(project_dir /
          subdir)`` + mkdir; absent → the COMMON home verbatim.

    Dependencies:
        Uses:
            - _check_home_contained
        Used by:
            - s19_app.tui.app.S19TuiApp._change_doc_save_home
            - s19_app.tui.crc_designer_view.CrcDesignerPanel._save_template
    """
    if project_dir is None:
        return common_home
    home = _check_home_contained(project_dir / subdir)
    home.mkdir(parents=True, exist_ok=True)
    return home


def scoped_home_target(
    project_dir: Optional[Path],
    subdir: str,
    common_home: Path,
) -> Path:
    """
    Summary:
        Resolve the change-1 scoped home's PATH without creating anything
        (batch-95 change 2, HLR-139): the exact home :func:`scoped_home`
        would return — with a project ``project_dir / subdir``, without one
        the COMMON ``common_home`` — but observed, not made. The open-folder
        chips need the missing-folder state to stay observable (a chip whose
        target was resolved by calling :func:`scoped_home` could never dim:
        the mkdir inside would have just created it), so the one-line
        project-vs-COMMON ruling lives here, beside its creating twin, and
        the chips ride it with no per-file guessing (LLR-139.1). The
        create-on-press offer still calls :func:`scoped_home`, so the
        containment law holds at every byte-writing seam.

    Args:
        project_dir (Optional[Path]): The active project's directory, or
            ``None`` without a project.
        subdir (str): The per-artifact project subfolder
            (:data:`PROJECT_PATCHES_DIR` / :data:`PROJECT_CHECKS_DIR` /
            :data:`PROJECT_TEMPLATES_DIR`).
        common_home (Path): The COMMON home kept when no project is
            active.

    Returns:
        Path: The resolved home path. Not created, not containment-checked
            (the chip opens or offers to create it; creation re-runs
            :func:`scoped_home`'s checks).

    Data Flow:
        - ``project_dir`` present → ``project_dir / subdir``; absent →
          ``common_home`` verbatim. Pure path arithmetic — no IO.

    Dependencies:
        Uses:
            - (path arithmetic only)
        Used by:
            - s19_app.tui.services.folder_open_service.resolve_chip_target
    """
    if project_dir is None:
        return common_home
    return project_dir / subdir
