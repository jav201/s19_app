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

Snapshot semantics (LLR-138.4): every gather is a COPY stamped at save
time, placed through HLR-155's placement (LLR-155.1/.2,
:func:`place_into_workarea`). The placement's byte-identity reuse decision
(its ``PlacementResult.reused`` flag, case-folded on Windows, the requested
name and every existing ``_<N>`` sibling) is the SOLE judge of "already
there" (security finding SEC2-7, round 4): a destination whose bytes
already equal the source is reused as-is, so an idempotent re-save stays
duplicate-free even after drifts (an unchanged re-save reuses the placed
``_<N>`` copy instead of stacking another one); a destination that drifted
from the source is never overwritten in place — since Inc 3b (LLR-155.3,
amended by LED-2026-10-25-batch-99.7) the changed copy takes the next free
``_<N>`` name, so a placed artifact is immutable once placed.
Divergence from later COMMON edits is accepted — the same semantics as the
shipped binaries copy-in.

Containment (the shipped law): every gathered byte resolves under
``<base>/.s19tool/workarea/`` — the destination re-runs ``place_into_workarea``'s
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
import os
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from .. import workspace as _workspace
from ..workspace import (
    A2L_EXTENSIONS,
    MAC_EXTENSIONS,
    WorkareaContainmentError,
    _find_workarea_root,
    _guarded_destination,
    _is_reparse_point,
    _path_traverses_reparse_point,
    place_into_workarea,
    predict_placement,
    validate_project_files,
    walk_tree_no_links,
)
from .variant_execution_service import (
    MANIFEST_ARTIFACT,
    PROJECT_MANIFEST_NAME,
    _clip,
    _manifest_key_refusal,
    _plain_entry,
    is_active_document_form,
)

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

#: Gather finding — the active document is not recorded as
#: ``active_document``: it sits in the project but not directly in its
#: kind's home, or its landing is not a ``.json`` name the manifest
#: accepts (LLR-170.2). A WARNING: the save proceeds without the key.
GATHER_DOCUMENT_NOT_RECORDED = "GATHER-DOCUMENT-NOT-RECORDED"

#: The four classes of a file-backed active document
#: (:func:`classify_active_document`, E3 R11).
DOCUMENT_IN_HOME = "in_home"
DOCUMENT_OUTSIDE = "outside"
DOCUMENT_INSIDE_ELSEWHERE = "inside_elsewhere"
DOCUMENT_MISSING = "missing"

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


def document_in_home(project_dir: Path, source: Path, home: str) -> bool:
    """
    Summary:
        The one test for "the file-backed document is already in its home"
        (A3-9, LLR-167.6, LLR-170.2): the class ``in_home`` of
        :func:`classify_active_document`.

    Args:
        project_dir (Path): The project folder, as the app names it
            (unresolved).
        source (Path): The document's file, unresolved.
        home (str): The home of its kind (``"patches"`` / ``"checks"``).

    Returns:
        bool: True only when ``f"{home}/{source.name}"`` passes
            ``is_active_document_form``, the source's folder is named
            ``home`` exactly (case-sensitive, A3R2-7), that folder's parent
            is ``project_dir`` (absolute paths compared as exact text, never
            case-folded and never resolved: a case-sensitive work area holds
            ``P`` and ``p`` as two projects, SEC8a-1), and
            ``os.lstat`` finds the home a regular folder and the source a
            regular file, neither a link nor a reparse point.

    Raises:
        None: Any ``OSError`` or ``ValueError`` gives False.

    Dependencies:
        Uses:
            - is_active_document_form / _plain_entry
        Used by:
            - classify_active_document
    """
    try:
        absolute = Path(os.path.abspath(source))
        if not is_active_document_form(f"{home}/{absolute.name}"):
            return False
        if absolute.parent.name != home:
            return False
        if str(absolute.parent.parent) != os.path.abspath(project_dir):
            return False
    except (OSError, ValueError):
        return False
    return _plain_entry(Path(project_dir) / home, folder=True) and _plain_entry(
        absolute, folder=False
    )


def classify_active_document(
    project_dir: Path, source: Path, home: str
) -> tuple[str, Optional[str]]:
    """
    Summary:
        The one gather classifier of a file-backed active document (E3 R11):
        the planner, the gather and the app's plan all call it, so the plan
        and the written tree agree.

    Args:
        project_dir (Path): The project folder the save writes, unresolved.
        source (Path): The document's file, unresolved.
        home (str): The home of its kind (``"patches"`` / ``"checks"``).

    Returns:
        tuple[str, Optional[str]]: ``(kind, name)``. ``kind`` is
            :data:`DOCUMENT_IN_HOME` (recorded as it is, ``keep``),
            :data:`DOCUMENT_OUTSIDE` (copied into the home),
            :data:`DOCUMENT_INSIDE_ELSEWHERE` or :data:`DOCUMENT_MISSING`
            (no row, nothing copied). ``name`` is the source's file name
            for the first two, ``None`` for the other two.

    Raises:
        None.

    Data Flow:
        - ``os.lstat(source)``: absent, unreadable, not a regular file, or
          a link or reparse point → ``missing`` (a link is never followed
          or copied, S3R2-5).
        - "Inside the project" is decided on the UNRESOLVED exact text
          (``os.path.abspath``, no case folding, no ``resolve()``, SEC8a-1):
          inside and :func:`document_in_home` → ``in_home``; inside
          otherwise → ``inside_elsewhere``.
        - Outside: a source under a ``.s19tool/workarea`` whose folders
          below that root include a link or junction → ``missing`` (R18:
          another project's ``patches`` swapped for a junction is never
          read through); otherwise ``outside``.

    Dependencies:
        Uses:
            - document_in_home / _plain_entry
            - workspace._find_workarea_root /
              workspace._path_traverses_reparse_point
        Used by:
            - plan_project_save / gather_project_artifacts
            - s19_app.tui.app.S19TuiApp._plan_project_save
    """
    if not _plain_entry(Path(source), folder=False):
        return DOCUMENT_MISSING, None
    try:
        absolute = Path(os.path.abspath(source))
        project_text = os.path.abspath(project_dir)
    except (OSError, ValueError):
        return DOCUMENT_MISSING, None
    if str(absolute).startswith(project_text + os.sep):
        if document_in_home(project_dir, source, home):
            return DOCUMENT_IN_HOME, absolute.name
        return DOCUMENT_INSIDE_ELSEWHERE, None
    workarea = _find_workarea_root(absolute)
    if workarea is not None and _path_traverses_reparse_point(
        absolute, stop_at=workarea
    ):
        return DOCUMENT_MISSING, None
    return DOCUMENT_OUTSIDE, absolute.name


def _check_home_contained(home: Path, workarea_root: Optional[Path] = None) -> Path:
    """
    Summary:
        Run the ONE shared workspace destination guard
        (:func:`workspace._guarded_destination`, LLR-171.4 as amended by
        LED .49, review finding F1) against a project home directory: the
        work-area root is taken from the home AS GIVEN, before any
        resolution — the nearest ``.s19tool/workarea`` ancestor of the
        unresolved path — the reparse walk runs on the unresolved path, and
        only then are the two sides resolved and compared.  A caller that
        pre-resolved the home would hide the junctions the guard exists to
        refuse (the executed S-02 probe wrote into another work area that
        way).

    Args:
        home (Path): The intended project home directory
            (``<project>/<home-name>/``), passed UNRESOLVED.
        workarea_root (Optional[Path]): An explicit work-area root the
            app-level caller passes (B100-I14, security finding SEC-1,
            LED .50) — the containment authority for the resolved pair.
            None derives the root from ``home``'s own textual path.

    Returns:
        Path: The resolved home, when contained.

    Raises:
        WorkareaContainmentError: When the home has no
            ``.s19tool/workarea`` ancestor, escapes that root after
            resolution, or traverses a reparse point.

    Data Flow:
        - ``_guarded_destination(home, workarea_root)`` — the same guard
          both placement kinds run (LLR-163.1, LED .49/.50), on the
          unresolved home.

    Dependencies:
        Uses:
            - _guarded_destination (the one destination guard, LLR-171.4)
        Used by:
            - _gather_copy
            - scoped_home
    """
    resolved, _root = _guarded_destination(home, workarea_root)
    return resolved


def _gather_copy(
    source: Path, home: Path, workarea_root: Optional[Path] = None
) -> tuple[bool, Path]:
    """
    Summary:
        Copy one used artifact into its contained project home with the
        snapshot semantics (LLR-138.4), placed through HLR-155's placement
        (:func:`place_into_workarea`). The placement is the SOLE judge of
        reuse (security finding SEC2-7, round 4): its byte-identity rule —
        the requested name and every ``_<N>`` sibling, case-folded on
        Windows — decides whether a destination already holds the source's
        exact bytes, and this function translates only the placement's own
        ``PlacementResult.reused`` flag into the gather's ``copied`` word.
        The gather holds NO name-based or byte-based pre-check of its own:
        a case-variant byte-identical file (``BOOST.json`` for a
        ``boost.json`` source) is reported as REUSED by the placement, so a
        failed save's rollback never deletes a pre-existing user file.

    Args:
        source (Path): The artifact's current on-disk path (the COMMON
            original or an arbitrary origin — the COPY ruling leaves the
            source untouched).
        home (Path): The destination project home directory, passed
            UNRESOLVED (LLR-171.4, LED .49): the guard reads the work-area
            root off its textual path before any resolution. Must land
            inside ``.s19tool/workarea/`` after resolution.
        workarea_root (Optional[Path]): An explicit work-area root the
            app-level caller passes (B100-I14, security finding SEC-1,
            LED .50) — threaded to the guard and the placement. None
            derives the root from ``home``'s own textual path.

    Returns:
        tuple[bool, Path]: ``(copied, destination)`` — ``copied`` is
            ``False`` when the placement REUSED a byte-identical existing
            file (its ``reused`` flag is True — nothing was written),
            ``True`` when the placement claimed and filled a name;
            ``destination`` is the resolved target file either way — the
            reused sibling on a reuse, the next free ``_<N>`` name on
            drift.

    Raises:
        WorkareaContainmentError: When ``home`` fails the containment
            checks (the escape-refusal limb) or the placement refuses.
        OSError: When the read/compare fails mid-copy.
        FileNotFoundError: When ``source`` does not exist.

    Data Flow:
        - ``_check_home_contained(home, workarea_root)`` first — no byte
          moves before the containment verdict; the guard sees the home
          UNRESOLVED.
        - ``place_into_workarea`` receives the UNRESOLVED home and the
          SAME explicit root, stages privately and claims the next free
          name — never an ``unlink``/recopy onto an existing final name;
          its reuse decision alone sets ``copied``.

    Dependencies:
        Uses:
            - _check_home_contained
            - place_into_workarea (the placement, LLR-155.1/.2, and the
              sole byte-identity judge, LLR-163.1)
        Used by:
            - gather_project_artifacts
    """
    _check_home_contained(home, workarea_root)
    placed = place_into_workarea(source, home, workarea_root=workarea_root)
    return not placed.reused, placed.path


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
        written (list[Path]): The files this gather actually WROTE —
            absolute paths, in placement order. A destination whose bytes
            already equalled the source (a reuse) never appears here
            (LED .53: a failed save removes exactly what the save
            created, so the rollback consumes this list verbatim).
        created_homes (list[Path]): The project home folders this gather
            created on demand — they did not exist when the gather
            started. A pre-existing home never appears here.
        active_document (Optional[str]): The project-relative POSIX text of
            the placed active document, ``f"{home}/{landing name}"`` built
            from the home constant (A3-12) — copied this save or already in
            its home; ``None`` when there is no document, it was not
            placed, or the text fails ``is_active_document_form``.
        unrecorded (tuple[str, ...]): The project-relative POSIX text of
            every gathered file placed in the project (written or reused)
            that ``project.json`` cannot record, sorted (LLR-171.5). The
            active document is never listed here: it keeps its own
            ``GATHER-DOCUMENT-NOT-RECORDED`` finding (pre-ruling 7).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`gather_project_artifacts`.
        - Consumed by ``S19TuiApp._handle_save_dialog``, which threads
          ``gathered`` into the manifest write (``manifest_writer``) and,
          on a failure exit, rolls the save back through
          ``S19TuiApp._abort_save`` with ``written`` / ``created_homes``
          (LED .53, LLR-164.4).

    Dependencies:
        Used by:
            - s19_app.tui.app.S19TuiApp._handle_save_dialog
    """

    gathered: dict[str, list[str]] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)
    written: list[Path] = field(default_factory=list)
    created_homes: list[Path] = field(default_factory=list)
    active_document: Optional[str] = None
    unrecorded: tuple[str, ...] = ()


def gather_project_artifacts(
    project_dir: Path,
    *,
    composition_names: Sequence[str] = (),
    active_document: Optional[Path] = None,
    active_document_kind: str = "change",
    active_template: Optional[Path] = None,
    common_patches_dir: Path,
    common_templates_dir: Path,
    workarea_root: Path,
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
            document path, when one is loaded, UNRESOLVED (E3 R11); for a
            pasted document, the landing the app wrote.
        active_document_kind (str): That document's wire ``kind`` (the
            in-memory discriminator — the file itself is the source).
        active_template (Optional[Path]): The CRC Designer's last
            successfully loaded template path, when one was loaded.
        common_patches_dir (Path): The COMMON change/check library
            (``<base>/.s19tool/workarea/patches/``) — the composition
            fallback resolution root.
        common_templates_dir (Path): The COMMON CRC template library
            (``<base>/.s19tool/templates/``).
        workarea_root (Path): An explicit work-area root the app-level
            caller passes (B100-I14, security finding SEC-1, LED .50) —
            REQUIRED, keyword-only, no default: it is threaded to every
            :func:`_gather_copy` so each placement's containment authority
            is THIS app's work area.  The gather never derives the root
            from a home's own textual path — review finding R3-3: that
            default let a junctioned project folder escape into another
            work area (probe ``r3_gather_projjunction.py``); omitting the
            root is a ``TypeError`` at the boundary.  The private seams
            (``_check_home_contained`` / ``_gather_copy``) keep their
            ``None`` derivation for the scoped-home callers that predate
            the root threading (``scoped_home``, itself routed to the
            LED .50 backlog with SEC-3).

    Returns:
        GatherOutcome: The ``gathered`` manifest rows + collected
        per-artifact findings + the exact-created lists (``written``
        files and ``created_homes`` folders, LED .53). Zero used
        artifacts → empty ``gathered`` + empty ``issues`` — the empty
        save is never an error (QC-3 boundary catalog).

    Raises:
        None: Every failure mode is a collected finding
            (collect-don't-abort, C-5) — a refused or missing artifact
            never blocks the save.

    Data Flow:
        - Build the used set: composition names (project-dir hit → already
          home; COMMON hit by bare name → gather; neither → one
          ``GATHER-SOURCE-MISSING`` finding) + the active document + the
          active template.
        - The active document is classified first, on the UNRESOLVED paths
          (:func:`classify_active_document`): ``in_home`` → not copied,
          named in ``outcome.active_document``; ``outside`` → copied (the
          unresolved source is passed to the placement, R18) and named by
          its landing; ``inside_elsewhere`` → one
          ``GATHER-DOCUMENT-NOT-RECORDED``; ``missing`` → one
          ``GATHER-SOURCE-MISSING`` (absent) or ``GATHER-CONTAINMENT`` (a
          link or not a regular file). A landing text that fails
          ``is_active_document_form`` stays copied, unnamed, with one
          ``GATHER-DOCUMENT-NOT-RECORDED``.
        - De-duplicate by resolved source path so a document both
          referenced and active is gathered once.
        - Each artifact COPYs through :func:`_gather_copy` into its home;
          successes append the project-relative POSIX path to
          ``gathered[home]`` (sorted per home, canonical home order).
          LED .53: each WRITTEN destination also appends to
          ``outcome.written`` and a home the copy created on demand
          appends to ``outcome.created_homes`` — a reused byte-identical
          sibling and a pre-existing home never appear, so a failed
          save's rollback removes exactly what this gather created.
        - A placed row (written or reused) whose project-relative text
          ``project.json`` cannot record stays out of ``gathered`` and is
          named in ``outcome.unrecorded`` (LLR-171.5); the active document
          is never named there.

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
        ...     workarea_root=workarea,
        ... )
    """
    outcome = GatherOutcome()
    resolved_project = project_dir.resolve()
    # resolved source → (home name, the path handed to the placement)
    pending: dict[Path, tuple[str, Path]] = {}

    def _schedule(source: Path, home: str, unresolved: bool = False) -> Path:
        try:
            resolved_source = source.resolve()
        except OSError:
            resolved_source = source
        if resolved_source in pending:
            if unresolved:
                pending[resolved_source] = (pending[resolved_source][0], source)
            return resolved_source
        pending[resolved_source] = (home, source if unresolved else resolved_source)
        return resolved_source

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

    # Predicate limb 2a — the active editor document, classified on the
    # unresolved paths before anything is resolved (E3 R11, S3R2-5).
    document_key: Optional[Path] = None
    if active_document is not None:
        document_home = document_home_for_kind(active_document_kind)
        kind, name = classify_active_document(
            project_dir, active_document, document_home
        )
        if kind == DOCUMENT_IN_HOME:
            outcome.active_document = f"{document_home}/{name}"
        elif kind == DOCUMENT_OUTSIDE:
            document_key = _schedule(active_document, document_home, unresolved=True)
        elif kind == DOCUMENT_INSIDE_ELSEWHERE:
            outcome.issues.append(
                _gather_issue(
                    GATHER_DOCUMENT_NOT_RECORDED,
                    f"gather: active document {active_document} is in the "
                    f"project but not directly in {document_home}/ — not "
                    f"recorded",
                )
            )
        elif not os.path.lexists(active_document):
            outcome.issues.append(
                _gather_issue(
                    GATHER_SOURCE_MISSING,
                    f"gather: active document {active_document} no "
                    f"longer exists — skipped",
                )
            )
        else:
            outcome.issues.append(
                _gather_issue(
                    GATHER_CONTAINMENT,
                    f"gather: active document {active_document} is a link, "
                    f"goes through a link or junction, or is not a regular "
                    f"file — not copied",
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
    unrecorded: list[str] = []
    for resolved_source, (home, source) in sorted(
        pending.items(), key=lambda item: str(item[0])
    ):
        home_dir = resolved_project / home
        # LED .53 / R5-1: remember what THIS gather creates — the home's
        # existence BEFORE the copy decides ``created_homes`` (a reused
        # byte-identical sibling requires a pre-existing home, so a
        # created home implies bytes were written into it).
        home_preexisted = home_dir.is_dir()
        try:
            copied, destination = _gather_copy(source, home_dir, workarea_root)
        except (WorkareaContainmentError, OSError) as exc:
            outcome.issues.append(
                _gather_issue(
                    GATHER_CONTAINMENT,
                    f"gather: refused to copy {resolved_source} into "
                    f"{home_dir}: "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            # R5-1 (review round 5): the placement mkdirs the home BEFORE
            # staging — a copy that then fails (a full disk, a source that
            # vanished) still leaves a home THIS gather created. Record it
            # from whether it now exists, on BOTH paths, never from
            # whether the copy wrote; the rollback removes a folder only
            # while it is empty, so this is safe.
            if (
                not home_preexisted
                and home_dir.is_dir()
                and home_dir not in outcome.created_homes
            ):
                outcome.created_homes.append(home_dir)
            continue
        if copied:
            outcome.written.append(destination)
        if (
            not home_preexisted
            and home_dir.is_dir()
            and home_dir not in outcome.created_homes
        ):
            outcome.created_homes.append(home_dir)
        relative = destination.relative_to(resolved_project).as_posix()
        # Review F1: a row project.json cannot hold (a device stem) is
        # copied but not listed, so it never refuses the manifest write;
        # LLR-171.5: it is named in ``unrecorded`` instead, except the
        # active document, which keeps its own finding (pre-ruling 7).
        if _manifest_key_refusal(relative) is None:
            gathered_rows.setdefault(home, []).append(relative)
        elif resolved_source != document_key:
            unrecorded.append(relative)
        if resolved_source == document_key:
            # A3-12: built from the home constant and the landing's name,
            # never from the resolved path.
            text = f"{home}/{destination.name}"
            if is_active_document_form(text):
                outcome.active_document = text
            else:
                outcome.issues.append(
                    _gather_issue(
                        GATHER_DOCUMENT_NOT_RECORDED,
                        f"gather: active document copied to {text}, a name "
                        f"project.json does not record — not recorded",
                    )
                )
    outcome.gathered = {
        home: sorted(rows)
        for home, rows in sorted(
            gathered_rows.items(),
            key=lambda item: PROJECT_HOME_NAMES.index(item[0]),
        )
    }
    outcome.unrecorded = tuple(sorted(unrecorded))
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


# ---------------------------------------------------------------------------
# The Save project plan (batch-100 B100-I17, LLR-167.6, R-PC)
# ---------------------------------------------------------------------------

#: Save-plan action words (LLR-167.6). Inc 5 produces ``new``, ``keep`` and
#: ``rewrite``; ``merge`` is added at 8a; ``replace`` is not produced at 8a
#: (E3 R1: Save project never overwrites a file in the project).
PLAN_ACTION_NEW = "new"
PLAN_ACTION_KEEP = "keep"
PLAN_ACTION_REWRITE = "rewrite"
PLAN_ACTION_MERGE = "merge"

#: Save-plan target kinds (LLR-167.6): a folder this save creates, the open
#: project, or another existing project the save merges into.
PLAN_TARGET_NEW = "new"
PLAN_TARGET_OPEN = "open project"
PLAN_TARGET_MERGE = "merge"

#: The row role of the ``project.json`` row.
PLAN_ROLE_MANIFEST = "manifest"

#: The row role of the active change or check document (LLR-167.6, 8a).
PLAN_ROLE_DOCUMENT = "document"

#: The row role of a top-level file of the open project that a save as
#: copies as it is (R3, LLR-167.6): one row per such file.
PLAN_ROLE_CARRIED = "carried"

#: Save-as ceilings (R1, R13, LLR-171.1j), read at call time so a test can
#: lower one constant: copyable files, walked entries (folders, links,
#: unreadable entries and files) and path components below the project.
SAVE_AS_FILE_CEILING = 2000
SAVE_AS_ENTRY_CEILING = 10000
SAVE_AS_DEPTH_CEILING = 32

#: ``ProjectInventory.over_ceiling`` values: the ceiling the walk stopped at.
OVER_CEILING_FILES = "files"
OVER_CEILING_ENTRIES = "entries"
OVER_CEILING_DEPTH = "depth"

#: Free-space rule (R7, LLR-171.1i): each file rounded up to this block,
#: plus the margin for ``project.json`` and the folders of a new target.
_SPACE_BLOCK_BYTES = 4096
_NEW_TARGET_MARGIN_BYTES = 65536

#: Unicode categories :func:`painted_names` removes (S3R2-4): controls,
#: format characters (bidi, zero-width, soft hyphen, tags) and the line and
#: paragraph separators.
_UNPAINTED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

#: Windows reserved device stems (S3R2-6): a name whose stem is one of these
#: can open the device, so the inventory never reads it.
_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{n}" for n in range(1, 10)}
    | {f"LPT{n}" for n in range(1, 10)}
)


#: The most names one painted list shows before ``and K more`` (R6,
#: LLR-171.7a); the one definition (F6).
PAINTED_NAME_LIMIT = 10


def painted_names(
    names: Sequence[str], limit: int = PAINTED_NAME_LIMIT, clip: int = 120
) -> str:
    """
    Summary:
        The one way a name taken from the open project's tree reaches
        painted text (R6, S3-4, LLR-171.7 / .7a): each name scrubbed and
        clipped, at most ``limit`` names, then ``and K more``.

    Args:
        names (Sequence[str]): The names, in the order to paint.
        limit (int): How many names are shown.
        clip (int): The most characters one painted name keeps.

    Returns:
        str: The first ``limit`` names joined with ``", "``, followed by
            ``", and K more"`` when more were given; ``""`` for no names.

    Data Flow:
        - Every character of Unicode category Cc, Cf, Zl or Zp is removed
          and every unpaired surrogate (Cs) becomes U+FFFD (S3R2-4), so the
          text always encodes as UTF-8.
        - Then each name is cut to ``clip`` characters with the clip
          ``variant_execution_service._clip`` uses (ending in "…").
        - Pure: the full list goes to the log from the caller, never here.

    Dependencies:
        Uses:
            - unicodedata.category / variant_execution_service._clip
        Used by:
            - plan_project_save / _second_file_refusal (refusal texts)
            - s19_app.tui.app.S19TuiApp._handle_save_dialog (status lines)

    Example:
        >>> painted_names(["a", "b\u202ec"], limit=1)
        'a, and 1 more'
    """
    items = list(names)
    shown = [_clip(_scrubbed(name), clip) for name in items[:limit]]
    text = ", ".join(shown)
    if len(items) > limit:
        text += f", and {len(items) - limit} more"
    return text


def _scrubbed(name: str) -> str:
    """``name`` without Cc / Cf / Zl / Zp characters, surrogates as U+FFFD."""
    kept = []
    for char in name:
        category = unicodedata.category(char)
        if category in _UNPAINTED_CATEGORIES:
            continue
        kept.append("\ufffd" if category == "Cs" else char)
    return "".join(kept)


@dataclass(frozen=True)
class InventoryFile:
    """
    Summary:
        One regular file of the walked project that a save as may copy
        (pre-ruling 1, LLR-171.1): at the top level (``relative`` is its
        bare name, R3) or under a top-level sub-folder (``relative`` is its
        project-relative POSIX text).

    Args:
        relative (str): Project-relative POSIX text, e.g.
            ``"flows/sub/g.json"``.
        size (int): Its ``os.lstat`` size, in bytes (the per-file cap,
            LLR-167.6g, and the free-space total, LLR-171.1i).
    """

    relative: str
    size: int


@dataclass(frozen=True)
class PlannedFolder:
    """
    Summary:
        One top-level sub-folder of the open project in a save-as plan
        (LLR-167.6a / .6b). A folder holding only links, or nothing, is
        still a row with ``file_count`` 0 (ruling Q9).

    Args:
        name (str): The top-level folder name.
        file_count (int): How many regular files the save copies under it,
            at any depth; equals ``len(files)``.
        skipped_links (tuple[str, ...]): Project-relative POSIX text of the
            links found under it, sorted.
        files (tuple[InventoryFile, ...]): Those files, sorted by
            ``relative``.
    """

    name: str
    file_count: int
    skipped_links: tuple[str, ...]
    files: tuple[InventoryFile, ...] = ()


@dataclass(frozen=True)
class ProjectInventory:
    """
    Summary:
        One link-free enumeration of the open project for a save as
        (:func:`inventory_project_tree`, LLR-171.1 / .1a / .1b / .1j / .1k).

    Args:
        root (Path): The unresolved folder that was walked (pre-ruling 2).
        folders (tuple[PlannedFolder, ...]): One per top-level sub-folder,
            sorted by name; a top-level directory link is not a folder.
        top_level (tuple[InventoryFile, ...]): Every top-level regular file
            that is not a link, sorted by name, except ``project.json`` and
            its ``project.json.previous-*`` backups (R3, R10).
        skipped_links (tuple[str, ...]): Every link or reparse point found,
            at any depth, sorted, project-relative.
        unreadable (tuple[str, ...]): Every folder the walk could not list
            (``"."`` for the project folder itself) and every entry it
            could not classify, sorted (R8, S3-2, S3R2-6).
        over_ceiling (Optional[str]): ``None``, or ``"files"`` /
            ``"entries"`` / ``"depth"`` when the walk stopped at a ceiling
            (R1, R13); the other fields are then partial.
    """

    root: Path
    folders: tuple[PlannedFolder, ...]
    top_level: tuple[InventoryFile, ...]
    skipped_links: tuple[str, ...]
    unreadable: tuple[str, ...]
    over_ceiling: Optional[str] = None


@dataclass(frozen=True)
class PlannedFile:
    """
    Summary:
        One file a Save project will place — an input of
        :func:`plan_project_save`. The digest and size are computed by the
        app (once per dialog open), so the planner hashes no payload.

    Args:
        role (str): ``"image"``, ``"mac"``, ``"a2l"`` or ``"document"``.
        source (Optional[Path]): The file the row derives from (for an
            emitted image, the loaded source); ``None`` for a pasted
            document, the unresolved file for a file-backed one.
        name (str): The requested landing name.
        digest (str): The SHA-256 hex digest of the bytes that will land.
        size (int): Their size, in bytes.
        home (Optional[str]): The project home the file lands in
            (``"patches"`` / ``"checks"`` for the document row); ``None``
            → the project folder itself.
    """

    role: str
    source: Optional[Path]
    name: str
    digest: str
    size: int
    home: Optional[str] = None


@dataclass(frozen=True)
class SavePlanRow:
    """
    Summary:
        One row of the save plan, at plan granularity (LLR-167.6).

    Args:
        role (str): ``"image"``, ``"mac"``, ``"a2l"``, ``"document"`` or
            ``"manifest"``.
        source (Optional[Path]): The row's source (``None`` for
            ``project.json`` and for a pasted document).
        landing (Path): The predicted full landing path, in the resolved
            form :func:`place_into_workarea` returns (under its home for
            the document row).
        action (str): One of the ``PLAN_ACTION_*`` words; ``new`` or
            ``keep`` for the document row.
    """

    role: str
    source: Optional[Path]
    landing: Path
    action: str


@dataclass(frozen=True)
class SavePlan:
    """
    Summary:
        The one Save project plan (B100-I17): what the save will write,
        computed without writing. ``_handle_save_dialog`` executes exactly
        these rows and the Save dialog paints them (R-PC). Frozen, so a
        reader cannot change what the handler executes.

    Args:
        target (Path): The project folder, as the app names it.
        target_kind (str): One of the ``PLAN_TARGET_*`` kinds.
        rows (tuple[SavePlanRow, ...]): The file rows, then ``project.json``.
        image (str): The image description — source + N change entries, K
            applied by this save, or an unchanged copy.
        manifest_keys (tuple[str, ...]): The ``project.json`` keys the app
            writes (an input, LED .45).
        refusal (Optional[str]): The refusal with its tokens; a refused plan
            has no rows.
        folders (tuple[PlannedFolder, ...]): The sub-folders a save as to a
            new folder copies (LLR-167.6a); empty for a merge, an
            open-project save, a save with no open project and a refused
            plan (LLR-171.1g).
        skipped_links (tuple[str, ...]): The inventory's links when
            ``folders`` is planned, else empty (LLR-167.6b).
        copies (tuple[InventoryFile, ...]): The copy list the app executes
            exactly (pre-ruling 1): the top-level copies first (R3), then
            the sub-folder files, each part in POSIX order, after the
            landing-owner rule (LLR-167.6e).
        total_bytes (int): Every file this save writes as new, each rounded
            up to 4 KiB, plus 64 KiB for a new folder (R7, R14,
            LLR-171.1i); 0 for a refused plan.
    """

    target: Path
    target_kind: str
    rows: tuple[SavePlanRow, ...]
    image: str
    manifest_keys: tuple[str, ...]
    refusal: Optional[str] = None
    folders: tuple[PlannedFolder, ...] = ()
    skipped_links: tuple[str, ...] = ()
    copies: tuple[InventoryFile, ...] = ()
    total_bytes: int = 0


def inventory_project_tree(project_dir: Path) -> ProjectInventory:
    """
    Summary:
        One link-free enumeration of the open project for a save as
        (LLR-171.1 / .1a / .1b / .1j / .1k, LLR-167.6a / .6b): writes
        nothing, hashes nothing, follows no link.

    Args:
        project_dir (Path): The open project's folder, unresolved.

    Returns:
        ProjectInventory: The folders, top-level files, links, unreadable
            entries and the ceiling the walk stopped at, if any. Two runs
            on one tree give equal inventories.

    Raises:
        None: An unlistable folder or an entry ``lstat`` cannot read is an
            ``unreadable`` entry, never an exception.

    Data Flow:
        - ``walk_tree_no_links(project_dir, unreadable=..., max_entries=
          SAVE_AS_ENTRY_CEILING)``: one walker, never descending into a
          reparse point; it reports every folder it could not list (R8).
        - Every yielded entry counts toward the entry ceiling (R13); the
          walker yields at most ``SAVE_AS_ENTRY_CEILING + 1`` entries, so
          they are collected first and past the ceiling →
          ``over_ceiling = "entries"`` with no entry classified (this
          ceiling takes precedence over the other two). More than
          ``SAVE_AS_DEPTH_CEILING`` path components → ``"depth"`` (R1).
        - A name ending in "." or " ", or whose stem (before the first dot,
          case-insensitive) is a reserved device name, is ``unreadable``
          before any ``lstat`` (S3-2, S3R2-6); entries below such a folder
          are not classified (the folder is already named).
        - ``os.lstat``: ``OSError`` → unreadable; a link or reparse point →
          ``skipped_links`` (and its top-level folder's list); a top-level
          directory → a folder row; a regular file → ``top_level`` or its
          folder's ``files``, except ``project.json`` and its
          ``project.json.previous-*`` backups (``normcase``, R10), which are
          neither listed nor counted; anything else → unreadable.
        - More than ``SAVE_AS_FILE_CEILING + 4`` counted files →
          ``over_ceiling = "files"`` (R1, R10: the copy list leaves out at
          most the image, MAC, A2L and the document's own file).
        - The ceilings are read at call time; the lists are not logged
          here (this module has no logging) — the app logs them.

    Dependencies:
        Uses:
            - workspace.walk_tree_no_links / workspace._is_reparse_point
            - os.lstat / stat
        Used by:
            - s19_app.tui.app.S19TuiApp._plan_project_save (save as)

    Example:
        >>> inventory = inventory_project_tree(project_dir)  # doctest: +SKIP
        >>> [folder.name for folder in inventory.folders]  # doctest: +SKIP
        ['flows', 'patches']
    """
    entry_ceiling = SAVE_AS_ENTRY_CEILING
    depth_ceiling = SAVE_AS_DEPTH_CEILING
    file_stop = SAVE_AS_FILE_CEILING + 4
    manifest_name = os.path.normcase(PROJECT_MANIFEST_NAME)
    backup_prefix = manifest_name + ".previous-"
    unlisted: list[Path] = []
    folder_files: dict[str, list[InventoryFile]] = {}
    folder_links: dict[str, list[str]] = {}
    top_level: list[InventoryFile] = []
    skipped_links: list[str] = []
    unreadable: list[str] = []
    over_ceiling: Optional[str] = None
    counted_files = 0
    walked = list(
        walk_tree_no_links(project_dir, unreadable=unlisted, max_entries=entry_ceiling)
    )
    if len(walked) > entry_ceiling:
        over_ceiling = OVER_CEILING_ENTRIES
        walked = []
    for relative in walked:
        parts = relative.parts
        if len(parts) > depth_ceiling:
            over_ceiling = OVER_CEILING_DEPTH
            break
        if any(_unopenable_name(part) for part in parts[:-1]):
            continue
        text = relative.as_posix()
        if _unopenable_name(parts[-1]):
            unreadable.append(text)
            continue
        path = project_dir / relative
        try:
            status = os.lstat(path)
        except OSError:
            unreadable.append(text)
            continue
        mode = status.st_mode
        if stat.S_ISLNK(mode) or _is_reparse_point(path):
            skipped_links.append(text)
            if len(parts) > 1:
                folder_links.setdefault(parts[0], []).append(text)
        elif stat.S_ISDIR(mode):
            if len(parts) == 1:
                folder_files.setdefault(parts[0], [])
        elif stat.S_ISREG(mode):
            if len(parts) == 1:
                name = os.path.normcase(parts[0])
                if name == manifest_name or name.startswith(backup_prefix):
                    continue
                top_level.append(InventoryFile(text, status.st_size))
            else:
                folder_files.setdefault(parts[0], []).append(
                    InventoryFile(text, status.st_size)
                )
            counted_files += 1
            if counted_files > file_stop:
                over_ceiling = OVER_CEILING_FILES
                break
        else:
            unreadable.append(text)
    unreadable.extend(path.as_posix() for path in unlisted)
    folders = tuple(
        PlannedFolder(
            name,
            len(files),
            tuple(sorted(folder_links.get(name, ()))),
            tuple(sorted(files, key=lambda item: item.relative)),
        )
        for name, files in sorted(folder_files.items())
    )
    return ProjectInventory(
        root=project_dir,
        folders=folders,
        top_level=tuple(sorted(top_level, key=lambda item: item.relative)),
        skipped_links=tuple(sorted(skipped_links)),
        unreadable=tuple(sorted(set(unreadable))),
        over_ceiling=over_ceiling,
    )


def _unopenable_name(name: str) -> bool:
    """True for a name Windows cannot open by its normal path (S3-2, S3R2-6):
    ending in "." or " ", or a reserved device stem before the first dot."""
    if name.endswith((".", " ")):
        return True
    return name.split(".", 1)[0].upper() in _RESERVED_STEMS


def _second_file_refusal(
    target: Path,
    existing: Sequence[Path],
    planned: PlannedFile,
    kind_label: str,
    exempt: frozenset[str],
) -> Optional[str]:
    """
    Summary:
        The single-MAC / single-A2L refusal of a save (LED .63 (b) / .66,
        LLR-167.6c / .6d / .6f): one rule for both kinds, decided before
        any folder exists.

    Args:
        target (Path): The project folder the save writes.
        existing (Sequence[Path]): The target's files of this kind (from
            ``validate_project_files``); empty for a target that does not
            exist.
        planned (PlannedFile): The session's file of this kind (the caller
            calls only when there is one).
        kind_label (str): ``"MAC"`` or ``"A2L"``.
        exempt (frozenset[str]): The target's MAC / A2L names that are the
            open project's own (same path, or same name and same bytes and
            not a link — decided by the app, pre-ruling 5).

    Returns:
        Optional[str]: ``None`` when ``existing`` is empty or an existing
            name (``normcase``) is exempt; otherwise the refusal text
            (token rows 4 / 5), every name through :func:`painted_names`.

    Data Flow:
        - Name comparison only; no digest is computed here (Inc 5 rule).

    Dependencies:
        Uses:
            - painted_names
        Used by:
            - plan_project_save
    """
    if not existing:
        return None
    exempt_names = {os.path.normcase(name) for name in exempt}
    if any(os.path.normcase(path.name) in exempt_names for path in existing):
        return None
    article = "an" if kind_label[:1] in "AEIOU" else "a"
    return (
        f"Project NOT saved: '{painted_names([Path(target).name])}' already "
        f"has {article} {kind_label} file "
        f"({painted_names([path.name for path in existing])}) — choose "
        f"another name."
    )


def _count_text(count: int) -> str:
    """``count`` with a space between thousands (``2 000``, ``10 000``)."""
    return f"{count:,}".replace(",", " ")


def _limit_text(limit: int) -> str:
    """The cap in MiB, or in bytes under 1 MiB (A3-7)."""
    mib = 1024 * 1024
    return f"{limit / mib:g} MiB" if limit >= mib else f"{limit} bytes"


def _rounded_up(size: int) -> int:
    """``size`` rounded up to a multiple of 4 096 (R7); 0 stays 0."""
    return -(-size // _SPACE_BLOCK_BYTES) * _SPACE_BLOCK_BYTES


def _walk_refusal(inventory: ProjectInventory) -> Optional[str]:
    """The R1 / R13 ceiling refusal, then the R8 unreadable refusal, of a
    save-as inventory (LLR-171.1j / .1k), in that precedence (A3-13)."""
    project = f"'{painted_names([inventory.root.name])}'"
    move = "move files out of the project, then save again."
    if inventory.over_ceiling == OVER_CEILING_FILES:
        return (
            f"Project NOT saved: {project} has too many files to copy "
            f"(over {_count_text(SAVE_AS_FILE_CEILING)}) — {move}"
        )
    if inventory.over_ceiling == OVER_CEILING_ENTRIES:
        return (
            f"Project NOT saved: {project} has too many files to copy "
            f"(over {_count_text(SAVE_AS_ENTRY_CEILING)} entries) — {move}"
        )
    if inventory.over_ceiling == OVER_CEILING_DEPTH:
        return (
            f"Project NOT saved: {project} has folders nested too deep "
            f"(over {SAVE_AS_DEPTH_CEILING} levels) — {move}"
        )
    if inventory.unreadable:
        names = [
            project if text == "." else text for text in inventory.unreadable
        ]
        return (
            f"Project NOT saved: {painted_names(names)} could not be read — "
            f"check that they can be opened, then save again."
        )
    return None


def _source_key(path: Path) -> str:
    """The unresolved, case-folded text the landing-owner rule compares."""
    return os.path.normcase(os.path.abspath(path))


def _plan_copies(
    inventory: ProjectInventory, files: Sequence[PlannedFile]
) -> tuple[tuple[PlannedFolder, ...], tuple[InventoryFile, ...], set[str]]:
    """
    Summary:
        The save-as copy list (R3, R10, pre-rulings 1 and 3, LLR-167.6e).

    Args:
        inventory (ProjectInventory): The open project's inventory.
        files (Sequence[PlannedFile]): The files the save places itself.

    Returns:
        tuple: ``(folders, copies, owned)`` — the folders without the
            document's own file, the copy list (top-level copies, then the
            sub-folder files, each part in POSIX order) and the source keys
            of the sub-folder files a document row owns.

    Data Flow:
        - Top level: ``inventory.top_level`` minus the names (``normcase``)
          of the image / MAC / A2L rows, minus every MAC file when a MAC
          row is planned and every A2L file when an A2L row is planned.
        - Sub-folders: each folder's files minus the file a document row
          names as its source (``root / relative``, ``normcase``): that row
          owns the landing.
    """
    row_names = {
        os.path.normcase(Path(planned.name).name)
        for planned in files
        if planned.home is None
    }
    has_mac = any(planned.role == "mac" for planned in files)
    has_a2l = any(planned.role == "a2l" for planned in files)
    top: list[InventoryFile] = []
    for item in inventory.top_level:
        suffix = os.path.splitext(item.relative)[1].lower()
        if os.path.normcase(item.relative) in row_names:
            continue
        if has_mac and suffix in MAC_EXTENSIONS:
            continue
        if has_a2l and suffix in A2L_EXTENSIONS:
            continue
        top.append(item)
    documents = {
        _source_key(planned.source)
        for planned in files
        if planned.role == PLAN_ROLE_DOCUMENT
        and planned.source is not None
        and planned.home is not None
    }
    owned: set[str] = set()
    folders: list[PlannedFolder] = []
    for folder in inventory.folders:
        kept = []
        for item in folder.files:
            key = _source_key(inventory.root / item.relative)
            if key in documents:
                owned.add(key)
            else:
                kept.append(item)
        folders.append(
            PlannedFolder(folder.name, len(kept), folder.skipped_links, tuple(kept))
        )
    nested = sorted(
        (item for folder in folders for item in folder.files),
        key=lambda item: item.relative,
    )
    return tuple(folders), tuple(top) + tuple(nested), owned


def plan_project_save(
    target: Path,
    *,
    target_kind: str,
    files: Sequence[PlannedFile],
    image: str,
    manifest_keys: Sequence[str],
    refusal: Optional[str] = None,
    inventory: Optional[ProjectInventory] = None,
    size_cap: Optional[int] = None,
    exempt: frozenset[str] = frozenset(),
) -> SavePlan:
    """
    Summary:
        Compute the Save project plan WITHOUT writing (B100-I17, LLR-167.6):
        every refusal first, then one row per top-level file, each landing
        name predicted by :func:`predict_placement` — the placement's own
        rule — with its action word, one ``carried`` row per top-level copy
        of a save as, and the ``project.json`` row. A pure function of its
        inputs and the target's listing: no byte is written and no payload
        is hashed (the digests are inputs).

    Args:
        target (Path): The project folder (it may not exist yet).
        target_kind (str): One of the ``PLAN_TARGET_*`` kinds.
        files (Sequence[PlannedFile]): The files the save places, in
            placement order.
        image (str): The image description the app composed.
        manifest_keys (Sequence[str]): The keys the app writes into
            ``project.json`` (LED .45: an input, so a new key changes no
            signature here).
        refusal (Optional[str]): A refusal the app found (row 9, a blocked
            re-derive); the plan then has no rows.
        inventory (Optional[ProjectInventory]): The open project's
            inventory, for a save as to a new folder (pre-ruling 4);
            ``None`` for a merge, an open-project save and a save with no
            open project.
        size_cap (Optional[int]): The per-file cap; ``None`` reads
            ``workspace.DEFAULT_COPY_SIZE_CAP_BYTES`` at call time.
        exempt (frozenset[str]): The target's MAC / A2L names that are the
            open project's own (pre-ruling 5, decided by the app).

    Returns:
        SavePlan: The frozen plan. A refused plan has 0 rows, 0 folders,
            0 links, 0 copies and total 0.

    Data Flow:
        - Refusal precedence (A3-13): (1) the passed ``refusal``; for a save
          as with an inventory, (2) a walk ceiling (R1, R13) and (3)
          unreadable entries (R8, ``"."`` painted as the project's name);
          (4) the copy list (:func:`_plan_copies`); (5) more than
          ``SAVE_AS_FILE_CEILING`` copies; (6) the MAC then the A2L rule
          (:func:`_second_file_refusal`, LED .66 / .63 (b)); (7) the
          per-file cap: the first planned file (row 6b), then the first
          copy (row 6a), with size > cap, whatever the action.
        - Each file → ``predict_placement(digest, size, target / home,
          name)`` (``target`` itself when ``home`` is None): a reuse is
          ``keep``, a claimed name is ``new``. A file-backed document row
          is classified first (:func:`classify_active_document`):
          ``in_home`` → ``keep``; ``outside`` → predicted;
          ``inside_elsewhere`` / ``missing`` → no row.
        - Save as with an inventory: a home row that does not own a
          sub-folder file is predicted against ``inventory.root / home``
          (the folder the sub-folder copy mirrors into the target before
          the rows loop, R2, DR-1); every home row's landing is spelled
          ``Path(target).resolve() / home / name`` (A3-9). One ``carried``
          row (action ``new``, landing ``target / name``) per top-level copy
          (R3, R11).
        - ``project.json`` → ``new`` when the target holds none; else
          ``merge`` for a merge target, else ``rewrite``.
        - ``total_bytes`` = the rounded sizes of the file rows whose action
          is ``new`` (carried rows left out, R14) + the rounded sizes of the
          copies + 64 KiB for a new target (R7).

    Dependencies:
        Uses:
            - predict_placement (B100-I22)
            - classify_active_document (E3 R11)
            - validate_project_files / _second_file_refusal
            - _walk_refusal / _plan_copies / painted_names
        Used by:
            - s19_app.tui.app.S19TuiApp._plan_project_save
    """
    keys = tuple(manifest_keys)

    def _refused(text: str) -> SavePlan:
        return SavePlan(target, target_kind, (), image, keys, text)

    if refusal is not None:
        return _refused(refusal)
    copying = target_kind == PLAN_TARGET_NEW and inventory is not None
    folders: tuple[PlannedFolder, ...] = ()
    links: tuple[str, ...] = ()
    copies: tuple[InventoryFile, ...] = ()
    owned: set[str] = set()
    if copying:
        walk_refusal = _walk_refusal(inventory)
        if walk_refusal is not None:
            return _refused(walk_refusal)
        folders, copies, owned = _plan_copies(inventory, files)
        links = inventory.skipped_links
        if len(copies) > SAVE_AS_FILE_CEILING:
            return _refused(
                f"Project NOT saved: '{painted_names([inventory.root.name])}' "
                f"has too many files to copy "
                f"(over {_count_text(SAVE_AS_FILE_CEILING)}) — move files out "
                f"of the project, then save again."
            )

    by_role = {planned.role: planned for planned in reversed(files)}
    if ("mac" in by_role or "a2l" in by_role) and Path(target).is_dir():
        data_files, a2l_files, _ = validate_project_files(Path(target))
        mac_files = [path for path in data_files if path.suffix.lower() in MAC_EXTENSIONS]
        for role, existing, label in (("mac", mac_files, "MAC"), ("a2l", a2l_files, "A2L")):
            if role in by_role:
                clash = _second_file_refusal(target, existing, by_role[role], label, exempt)
                if clash is not None:
                    return _refused(clash)

    cap = _workspace.DEFAULT_COPY_SIZE_CAP_BYTES if size_cap is None else size_cap
    limit = _limit_text(cap)
    for planned in files:
        if planned.size > cap:
            return _refused(
                f"Project NOT saved: {painted_names([planned.name])} is too "
                f"large to copy (over {limit}) — a project cannot hold files "
                f"over {limit}."
            )
    for item in copies:
        if item.size > cap:
            return _refused(
                f"Project NOT saved: {painted_names([item.relative])} is too "
                f"large to copy (over {limit}) — move it out of the project "
                f"folder, then save again."
            )

    rows: list[SavePlanRow] = []
    total = 0
    for planned in files:
        landing_dir = target if planned.home is None else Path(target) / planned.home
        name = planned.name
        if (
            planned.role == PLAN_ROLE_DOCUMENT
            and planned.source is not None
            and planned.home is not None
        ):
            kind, name = classify_active_document(target, planned.source, planned.home)
            if kind == DOCUMENT_IN_HOME:
                rows.append(
                    SavePlanRow(
                        planned.role,
                        planned.source,
                        landing_dir.resolve() / name,
                        PLAN_ACTION_KEEP,
                    )
                )
                continue
            if kind != DOCUMENT_OUTSIDE:
                continue
        predict_dir = landing_dir
        if copying and planned.home is not None:
            owns = planned.source is not None and _source_key(planned.source) in owned
            if not owns:
                predict_dir = inventory.root / planned.home
        predicted = predict_placement(planned.digest, planned.size, predict_dir, name)
        landing = predicted.path
        if copying and planned.home is not None:
            landing = Path(target).resolve() / planned.home / predicted.path.name
        action = PLAN_ACTION_KEEP if predicted.reused else PLAN_ACTION_NEW
        rows.append(SavePlanRow(planned.role, planned.source, landing, action))
        if action == PLAN_ACTION_NEW:
            total += _rounded_up(planned.size)
    for item in copies:
        if "/" not in item.relative:
            rows.append(
                SavePlanRow(
                    PLAN_ROLE_CARRIED,
                    inventory.root / item.relative,
                    Path(target).resolve() / item.relative,
                    PLAN_ACTION_NEW,
                )
            )
        total += _rounded_up(item.size)
    if target_kind == PLAN_TARGET_NEW:
        total += _NEW_TARGET_MARGIN_BYTES
    manifest = Path(target).resolve() / PROJECT_MANIFEST_NAME
    if not os.path.lexists(manifest):
        manifest_action = PLAN_ACTION_NEW
    elif target_kind == PLAN_TARGET_MERGE:
        manifest_action = PLAN_ACTION_MERGE
    else:
        manifest_action = PLAN_ACTION_REWRITE
    rows.append(SavePlanRow(PLAN_ROLE_MANIFEST, None, manifest, manifest_action))
    return SavePlan(
        target,
        target_kind,
        tuple(rows),
        image,
        keys,
        folders=folders,
        skipped_links=links,
        copies=copies,
        total_bytes=total,
    )
