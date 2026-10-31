from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterator, Optional, Sequence

from .models import ProjectVariantSet, VariantDescriptor


WORKAREA_DIRNAME = ".s19tool"
WORKAREA_SUBDIR = "workarea"
WORKAREA_TEMP = "temp"
#: Private per-write staging home under ``temp/`` (HLR-155 / LLR-155.1). Each
#: placement writes into its own ``tempfile.mkdtemp`` directory below this
#: one, so no two writes can ever share a staged file under a user name.
WORKAREA_STAGING_DIRNAME = ".staging"
WORKAREA_PATCHES = "patches"
LOGS_SUBDIR = "logs"
LOG_FILENAME = "s19tui.log"
# Reusable, cross-project CRC algorithm-template library (batch-58 LLR-V5.2, F3).
# A single fixed directory under ``.s19tool/`` — the Designer's Save writes only
# ``<sanitized-basename>.crc.json`` here, so a template name can never redirect the
# write outside this bounded directory.
WORKAREA_TEMPLATES = "templates"
#: Reserved work-area home names (HLR-162 / LLR-162.2): the closed set of
#: folder homes the tool manages — ``temp``, ``patches``, ``crc`` and
#: ``splits`` are created directly under the work area (the last two also
#: inside project dirs), ``templates`` / ``logs`` under ``.s19tool/``, and
#: ``flows`` / ``flowsets`` / ``reports`` inside project dirs; any of them can
#: appear at the work-area root. ``S19TuiApp.list_projects`` omits every name here, so no reserved
#: home can present as a project in the Load project dialog.
RESERVED_WORKAREA_HOMES = (
    WORKAREA_TEMP,
    WORKAREA_PATCHES,
    WORKAREA_TEMPLATES,
    LOGS_SUBDIR,
    "crc",
    "flows",
    "flowsets",
    "splits",
    "reports",
)
#: Maximum length of a sanitised project name (HLR-164 / LLR-164.3, ruling
#: Q-1): a longer name is refused before any folder is created.
PROJECT_NAME_MAX_CHARS = 64
#: Windows device-name bases refused as project names (HLR-164 / LLR-164.1):
#: the console family, the CON streams and the COM/LPT ports. Compared
#: case-folded, with or without an extension or a superscript digit.
_WINDOWS_DEVICE_BASES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
)
#: The Windows file namespace maps the superscript digits onto plain digits,
#: so ``COM¹`` names the same device as ``COM1`` (LLR-164.1).
_DEVICE_DIGIT_TRANSLATION = str.maketrans({"¹": "1", "²": "2", "³": "3"})
# Default size cap for ``copy_into_workarea``. Cap rationale (per security
# Finding S-N02): realistic A2L upper end is ~100 MB per
# ``tests/conftest.py`` generators; 256 MB leaves ~2.5x headroom. The cap is
# configurable per call to allow regression testing.
DEFAULT_COPY_SIZE_CAP_BYTES = 256 * 1024 * 1024


class WorkareaContainmentError(ValueError):
    """Raised when ``copy_into_workarea`` rejects an unsafe source or destination."""


class WorkareaPlacementError(WorkareaContainmentError):
    """Raised when a staged write cannot be placed under its claimed name.

    Subclass of :class:`WorkareaContainmentError` (LLR-155.2) so every caller
    that already handles a containment refusal reports a placement failure
    with no edit. The message leads with the outcome, names the file and the
    folder, gives the cause and the next step, and says nothing was written.
    """


@dataclass(frozen=True)
class PlacementResult:
    """The outcome of one placement (B100-I13).

    Summary:
        ``path`` is the file the placement landed on — a pre-existing file
        when ``reused`` is true (the byte-identical candidate the placement
        found), or the freshly claimed ``_<N>`` name when false. ``reused``
        is true only when the returned file existed before the call.

    Args:
        path (Path): The placed (or reused) file.
        reused (bool): True when ``path`` existed before the placement and
            its bytes were reused; nothing was written in that case.
    """

    path: Path
    reused: bool


S19_EXTENSIONS = {".s19", ".srec"}
HEX_EXTENSIONS = {".hex", ".ihex"}
MAC_EXTENSIONS = {".mac"}
A2L_EXTENSIONS = {".a2l"}
SUPPORTED_EXTENSIONS = S19_EXTENSIONS | HEX_EXTENSIONS | MAC_EXTENSIONS
PROJECT_DATA_EXTENSIONS = SUPPORTED_EXTENSIONS
PROJECT_PRIMARY_DATA_EXTENSIONS = S19_EXTENSIONS | HEX_EXTENSIONS


def ensure_workarea(base_dir: Path) -> Path:
    """Ensure workarea structure exists and return the workarea path."""
    workarea_root = base_dir / WORKAREA_DIRNAME
    workarea = workarea_root / WORKAREA_SUBDIR
    workarea.mkdir(parents=True, exist_ok=True)
    (workarea / WORKAREA_TEMP).mkdir(parents=True, exist_ok=True)
    (workarea / WORKAREA_PATCHES).mkdir(parents=True, exist_ok=True)
    (workarea_root / LOGS_SUBDIR).mkdir(parents=True, exist_ok=True)
    return workarea


def ensure_template_lib(base_dir: Path) -> Path:
    """
    Summary:
        Ensure the CRC template library directory exists and return it
        (batch-58 LLR-V5.2 / F3). The library is the single fixed
        ``<base_dir>/.s19tool/templates`` directory that the CRC Designer's Save
        writes ``*.crc.json`` templates into; the write basename is name-derived
        but the directory is fixed, so a template name can never escape it.

    Args:
        base_dir (Path): The app base directory (``S19TuiApp.base_dir``).

    Returns:
        Path: The (now-existing) ``<base_dir>/.s19tool/templates`` directory.

    Data Flow:
        - ``base_dir`` / :data:`WORKAREA_DIRNAME` / :data:`WORKAREA_TEMPLATES`,
          ``mkdir(parents=True, exist_ok=True)``.

    Dependencies:
        Used by:
            - s19_app.tui.crc_designer_view.CrcDesignerPanel (Save/Load)
    """
    lib = base_dir / WORKAREA_DIRNAME / WORKAREA_TEMPLATES
    lib.mkdir(parents=True, exist_ok=True)
    return lib


def setup_logging(base_dir: Path) -> logging.Logger:
    """Configure a rotating file logger under .s19tool/logs."""
    logs_dir = base_dir / WORKAREA_DIRNAME / LOGS_SUBDIR
    # Ensure the logs directory exists before creating or writing log files.
    # This creates the directory and any parent directories as needed,
    # without raising an error if it already exists.
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / LOG_FILENAME

    logger = logging.getLogger("s19tui")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Bound the handler set to a SINGLE RotatingFileHandler for this ``log_path``.
    # ``getLogger("s19tui")`` is process-global, so without pruning, every call
    # with a new ``base_dir`` would append another handler that is never closed.
    # Under the test suite (one ``setup_logging`` per ``S19TuiApp.__init__``,
    # thousands of app constructions across ~1000 TUI tests, each with a fresh
    # ``tmp_path``) the handlers grow unbounded: each log record then fans out
    # O(N) file writes, the suite slows progressively, and the accumulated open
    # handles block ``tmp_path`` cleanup on Windows -- the intermittent full-suite
    # global-state flake. Keep the handler already bound to this path (idempotent
    # re-init); remove + close any bound to a different path.
    handler_exists = False
    for handler in list(logger.handlers):
        if isinstance(handler, RotatingFileHandler):
            if getattr(handler, "baseFilename", None) == str(log_path):
                handler_exists = True
            else:
                logger.removeHandler(handler)
                handler.close()

    if not handler_exists:
        handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,
            backupCount=1,
            encoding="utf-8",
        )
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        try:
            log_path.touch(exist_ok=True)
        except Exception:
            pass
    return logger


def _is_reparse_point(path: Path) -> bool:
    """
    Summary:
        Return True when ``path`` is a symbolic link or a Windows reparse point (junction).

    Args:
        path (Path): Filesystem path to inspect. The path need not exist.

    Returns:
        bool: True if ``path`` is a symlink (POSIX or Windows) or carries the
            Windows ``FILE_ATTRIBUTE_REPARSE_POINT`` flag (NTFS junction). False otherwise.

    Raises:
        None: Missing paths and ``OSError`` from ``os.lstat`` are reported as False.

    Data Flow:
        - Try ``Path.is_symlink()`` first; that catches POSIX symlinks and Windows symbolic links.
        - On Windows, also probe ``os.lstat(path).st_file_attributes`` for the reparse-point flag
          because ``mklink /J`` directory junctions are reparse points but not symlinks (per
          security finding S-N01: ``Path.resolve()`` silently follows them).
        - Treat any ``OSError`` (path missing, permission, broken link) as False so the caller's
          containment check has the chance to reject for a more specific reason.

    Dependencies:
        Uses:
            - os.lstat
            - stat.FILE_ATTRIBUTE_REPARSE_POINT (Windows attribute constant)
        Used by:
            - _private_stage_dir
            - _path_traverses_reparse_point
            - copy_into_workarea
    """
    try:
        if path.is_symlink():
            return True
    except OSError:
        return False
    if sys.platform == "win32":
        try:
            attrs = os.lstat(path).st_file_attributes
        except (OSError, AttributeError):
            return False
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attrs & reparse_flag:
            return True
    return False


def walk_tree_no_links(
    root: Path,
    unreadable: Optional[list[Path]] = None,
    max_entries: Optional[int] = None,
) -> Iterator[Path]:
    """
    Summary:
        Yield every file and folder under ``root`` as a path RELATIVE to
        ``root``, never descending into a symbolic link or a Windows
        reparse point (junction). A reparse-point entry is yielded as a
        leaf and its target is never entered, so the walk cannot escape
        ``root`` and cannot loop on a junction cycle.

    Args:
        root (Path): Existing directory to walk.
        unreadable (Optional[list[Path]]): When given, the relative path of
            every folder that cannot be listed is appended to it before the
            folder is skipped (R8, DR-5); ``root`` itself is reported as
            ``Path(".")``.
        max_entries (Optional[int]): When given, the walk counts every
            entry it reads from ``os.scandir``; once the count passes
            ``max_entries`` it stops reading the current folder BEFORE
            sorting it, yields what it read, and ends — at most
            ``max_entries + 1`` entries in all, so one huge folder is never
            sorted whole (R13, S3R2-1).

    Returns:
        Iterator[Path]: Relative paths of all files and folders below ``root``,
            reparse points included as leaves.

    Raises:
        None: A folder that cannot be listed (``OSError`` from ``os.scandir``)
            is skipped, the same as ``list_projects`` treats it.

    Data Flow:
        - Iterate with ``os.scandir`` using ``entry.is_dir(follow_symlinks=False)``
          so symbolic links are never entered.
        - Re-check each directory child with ``_is_reparse_point`` (lstat-based)
          because on Python 3.11 a junction reads as a plain directory to
          ``DirEntry.is_dir(follow_symlinks=False)`` — this is the ONE
          non-following tree walk (review finding R3-1), kept for
          save-as (LLR-171.1); the Save project rollback no longer
          consumes it (LED .53: it walks no folder at all).
        - Depth-first via an explicit stack; reparse points are never pushed,
          so the walk terminates even on ``loop -> root`` cycles.
        - Callers that pass neither ``unreadable`` nor ``max_entries`` get
          the walk unchanged.

    Dependencies:
        Uses:
            - os.scandir
            - _is_reparse_point
        Used by:
            - project_gather_service.inventory_project_tree (save-as,
              LLR-171.1)
            - tests (the walker's unit arm)
    """
    stack = [root]
    read = 0
    while stack:
        current = stack.pop()
        listed = []
        stopped = False
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    listed.append(entry)
                    if max_entries is not None and read + len(listed) > max_entries:
                        stopped = True
                        break
        except OSError:
            if unreadable is not None:
                unreadable.append(current.relative_to(root))
            continue
        read += len(listed)
        entries = sorted(listed, key=lambda entry: entry.name)
        for entry in entries:
            child = current / entry.name
            yield child.relative_to(root)
            try:
                if entry.is_dir(follow_symlinks=False) and not _is_reparse_point(child):
                    stack.append(child)
            except OSError:
                continue
        if stopped:
            return


def _path_traverses_reparse_point(path: Path, stop_at: Optional[Path] = None) -> bool:
    """
    Summary:
        Walk ``path`` and every parent up to ``stop_at`` looking for symlinks or junctions.

    Args:
        path (Path): Path to inspect; may or may not exist.
        stop_at (Optional[Path]): Ancestor at which to stop the walk (exclusive). When None
            the walk continues to the filesystem root.

    Returns:
        bool: True if ``path`` itself or any traversed parent is a reparse point.

    Raises:
        None.

    Data Flow:
        - Inspect ``path`` directly with ``_is_reparse_point``.
        - Walk parents one level at a time until ``stop_at`` is reached, the filesystem root is
          reached, or a reparse point is found.

    Dependencies:
        Uses:
            - _is_reparse_point
        Used by:
            - copy_into_workarea
    """
    current = path
    if _is_reparse_point(current):
        return True
    while True:
        parent = current.parent
        if parent == current:
            return False
        if stop_at is not None and parent == stop_at:
            return False
        if _is_reparse_point(parent):
            return True
        current = parent


def _find_workarea_root(destination: Path) -> Optional[Path]:
    """
    Summary:
        Return the OUTERMOST ``<base>/.s19tool/workarea`` ancestor of
        ``destination`` if one exists (review finding N1, LED .50): the
        reparse walk must run up to the outermost anchor's ``.s19tool`` so a
        junction BETWEEN the app's work area and a nested anchor is checked
        — the parts between two anchors lie inside the outer work area, so
        checking them is correct.

    Args:
        destination (Path): Unresolved destination directory.

    Returns:
        Optional[Path]: The outermost ancestor (or self) that ends with
            ``.s19tool/workarea``, or None when no such ancestor exists.

    Raises:
        None.

    Data Flow:
        - Walk ``destination`` and each parent looking for the parts pair
          (``.s19tool``, ``workarea``), remembering the LAST match — the
          walk continues to the filesystem root so a nearer (nested) anchor
          never truncates the reparse check above it.

    Dependencies:
        Uses:
            - pathlib.Path
        Used by:
            - _guarded_destination (LLR-163.1, LED .50)
    """
    found: Optional[Path] = None
    candidate = destination
    if sys.platform == "win32":
        # review finding F8: the anchor parts compare case-insensitively on
        # Windows (``.S19TOOL\\WORKAREA`` names the same seam), while POSIX
        # keeps the exact spelling (a differently-cased directory there is a
        # DIFFERENT directory).
        dirname = WORKAREA_DIRNAME.casefold()
        subdir = WORKAREA_SUBDIR.casefold()
        same_anchor = (
            lambda parts: len(parts) >= 2
            and parts[-2].casefold() == dirname
            and parts[-1].casefold() == subdir
        )
    else:
        same_anchor = (
            lambda parts: len(parts) >= 2
            and parts[-2] == WORKAREA_DIRNAME
            and parts[-1] == WORKAREA_SUBDIR
        )
    while True:
        parts = candidate.parts
        if same_anchor(parts):
            found = candidate
        parent = candidate.parent
        if parent == candidate:
            return found
        candidate = parent


def _find_workarea_root_shortname(destination: Path) -> Optional[Path]:
    """
    Summary:
        8.3 short-name fallback for :func:`_find_workarea_root` (review
        finding F8): accept a destination whose ``.s19tool`` / ``workarea``
        anchor survives only in a non-canonical spelling the textual walk
        cannot match (an 8.3 short-name component such as ``S19TOO~1``) —
        a form the old resolve-first code accepted.  Every component up to
        the anchor is reparse-checked BEFORE it is resolved, so a junction
        or symlink in the chain is still refused and the anchor cannot
        silently resolve into another work area (the executed S-02 shape).

    Args:
        destination (Path): The UNRESOLVED, normalised destination whose
            textual ancestors hold no canonical anchor.

    Returns:
        Optional[Path]: The TEXTUAL prefix of ``destination`` whose
            resolution lands on the ``.s19tool/workarea`` anchor — the
            caller's reparse walk and containment comparison then run
            exactly as for a textual root.  None when no prefix resolves
            to the anchor.

    Raises:
        WorkareaContainmentError: When a component of the unresolved chain
            is a symbolic link or NTFS reparse point.

    Data Flow:
        - Extend one component at a time from the drive/root; refuse a
          reparse component via ``os.lstat`` (S-N01: resolve would follow
          it silently).
        - Resolve the prefix and compare its final two parts with the
          anchor, case-folded on Windows.
        - The last matching prefix wins (the OUTERMOST anchor), mirroring
          :func:`_find_workarea_root` (review finding N1, LED .50).

    Dependencies:
        Uses:
            - _is_reparse_point
        Used by:
            - _guarded_destination (LLR-163.1, LED .49)
    """
    fold = str.casefold if sys.platform == "win32" else (lambda text: text)
    anchor_dirname = fold(WORKAREA_DIRNAME)
    anchor_subdir = fold(WORKAREA_SUBDIR)
    found: Optional[Path] = None
    current = Path(destination.parts[0])  # the drive or filesystem root
    for part in destination.parts[1:]:
        current = current / part
        if _is_reparse_point(current):
            raise WorkareaContainmentError(
                "Refusing to place: destination traverses a symbolic link or "
                f"reparse point: {current}"
            )
        try:
            resolved_prefix = current.resolve()
        except OSError:
            return None
        resolved_parts = resolved_prefix.parts
        if (
            len(resolved_parts) >= 2
            and fold(resolved_parts[-2]) == anchor_dirname
            and fold(resolved_parts[-1]) == anchor_subdir
        ):
            found = current
    return found


def _private_stage_dir(workarea_root: Path) -> Path:
    """
    Summary:
        Create and return a private per-write staging directory under
        ``<workarea_root>/temp/.staging/`` (LLR-155.1), reparse-checked at
        both levels — the one staging home shared by every work-area writer
        (``copy_into_workarea``, ``save_patched_image`` and
        ``write_change_document``).

    Args:
        workarea_root (Path): The resolved ``.s19tool/workarea`` root whose
            ``temp/.staging/`` home hosts the staging directory.

    Returns:
        Path: A fresh ``tempfile.mkdtemp`` directory owned by the caller.
            The caller removes exactly this directory when done
            (LLR-155.7); the shared ``temp/.staging/`` home persists by
            design.

    Raises:
        WorkareaContainmentError: When ``temp`` or ``temp/.staging`` is a
            symbolic link or reparse point — probed with ``os.lstat``, so
            a dangling junction is caught by the check itself (security
            finding S-F3) — when the staging home cannot be prepared, or
            when the created staging directory fails the post-creation
            reparse/realpath re-verification (security finding S-F2). A
            containment-class refusal, never an uncaught ``OSError``
            (every caller already handles the class, LLR-155.2).

    Data Flow:
        - Both levels must be real directories: a reparse point at either
          level would let the staged bytes escape the work area (``Path.
          resolve`` silently follows them — security finding S-N01).
        - ``temp/`` is created on demand; the staging home itself is
          created (never followed) after its reparse check.
        - The per-write directory comes from ``tempfile.mkdtemp``, so
          concurrent writers never share a staging path. After the
          mkdtemp both levels are lstat-rechecked and the created
          directory's real path must stay under the work area's real
          path — a seam swapped for a link between the check and the
          mkdtemp is refused and the created directory removed
          (security finding S-F2).

    Dependencies:
        Uses:
            - tempfile.mkdtemp
            - _is_reparse_point
        Used by:
            - copy_into_workarea
            - s19_app.tui.changes.apply.save_patched_image
            - s19_app.tui.changes.io.write_change_document
    """
    temp_dir = workarea_root / WORKAREA_TEMP
    # Security finding S-F3: an lstat-based check, not ``exists()`` — a
    # dangling junction reports ``exists() == False`` (``Path.exists``
    # follows the link), so an ``exists()``-based guard never evaluates
    # the reparse check at all. ``os.lstat`` never follows the link, and
    # ``_is_reparse_point`` reports OSError (missing path) as False.
    if _is_reparse_point(temp_dir):
        raise WorkareaContainmentError(
            f"Refusing to stage: staging temp is a symbolic link or reparse point: {temp_dir}"
        )
    staging_root = temp_dir / WORKAREA_STAGING_DIRNAME
    if _is_reparse_point(staging_root):
        raise WorkareaContainmentError(
            f"Refusing to stage: staging home is a symbolic link or reparse point: {staging_root}"
        )
    try:
        temp_dir.mkdir(parents=True, exist_ok=True)
        staging_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # a blocked staging seam (a file in the way, a denied home) is a
        # containment-class refusal, never an uncaught OSError — every
        # caller already handles WorkareaContainmentError (LLR-155.2)
        raise WorkareaContainmentError(
            f"Refusing to stage: staging home cannot be prepared: {exc}"
        ) from exc
    try:
        stage_dir = Path(tempfile.mkdtemp(prefix="stage-", dir=staging_root))
    except OSError as exc:
        raise WorkareaContainmentError(
            f"Refusing to stage: private staging directory cannot be created: {exc}"
        ) from exc
    # Security finding S-F2: the mkdtemp race — between the reparse check
    # and the mkdtemp, the staging seam can be swapped for a link. Re-check
    # both levels with lstat and require the created directory's real path
    # to stay under the work area's real path; otherwise remove the
    # directory this call created and refuse.
    if _is_reparse_point(temp_dir) or _is_reparse_point(staging_root):
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise WorkareaContainmentError(
            "Refusing to stage: staging home became a symbolic link or "
            f"reparse point: {staging_root}"
        )
    if not os.path.realpath(stage_dir).startswith(
        os.path.realpath(workarea_root) + os.sep
    ):
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise WorkareaContainmentError(
            f"Refusing to stage: staging directory escaped the work area: {stage_dir}"
        )
    return stage_dir


def contained_in_workarea(path: Path, workarea: Path) -> bool:
    """
    Summary:
        True when ``path``, after resolving every link and junction, is
        inside ``workarea.resolve()`` — THIS work area, never inside some
        other ``.s19tool/workarea`` (LLR-171.4, B100-I14).

    Args:
        path (Path): The path to test; need not exist.
        workarea (Path): The work-area root the path must land inside.

    Returns:
        bool: True when the resolved path equals the resolved work area or
            sits below it; False on any ``OSError`` during resolution.

    Raises:
        None: Missing paths and ``OSError`` from ``Path.resolve`` report
            False so the caller's guard can refuse for a specific reason.

    Data Flow:
        - Resolve both sides fully (``Path.resolve`` follows links and
          junctions, per security finding S-N01 that is exactly what makes
          the resolved pair the right thing to compare).
        - Compare with equality-or-descendant (``is_relative_to``).

    Dependencies:
        Uses:
            - pathlib.Path.resolve / is_relative_to
        Used by:
            - place_into_workarea (LLR-163.1)
            - write_project_manifest's containment check (LLR-171.4)
    """
    try:
        resolved_path = Path(path).resolve()
        resolved_workarea = Path(workarea).resolve()
    except OSError:
        return False
    return (
        resolved_path == resolved_workarea
        or resolved_path.is_relative_to(resolved_workarea)
    )


def _guarded_destination(
    destination: Path,
    workarea_root: Optional[Path] = None,
) -> tuple[Path, Path]:
    """
    Summary:
        The ONE destination guard both placement kinds run (LLR-163.1 as
        amended by LED .49/.50, LLR-171.4, review findings F1/N1): the
        work-area root is taken from the destination AS GIVEN, before any
        resolution — the OUTERMOST ``.s19tool/workarea`` ancestor of the
        unresolved path (compared case-insensitively on Windows, with an 8.3
        short-name fallback for non-canonical anchor spellings), or the
        explicit root an app-level caller passes when it knows THIS app's
        work area (B100-I14) — and only THEN are the two sides resolved and
        compared, so a junction or link anywhere in the destination is
        caught.  Every caller passes its destination UNRESOLVED.

    Args:
        destination (Path): The UNRESOLVED destination directory, exactly
            as the caller's path names it.  A pre-resolved destination
            hides the junctions this guard exists to refuse (the executed
            S-02 probe).
        workarea_root (Optional[Path]): An explicit work-area root an
            app-level caller passes.  None derives the root from the
            destination's own textual path.

    Returns:
        tuple[Path, Path]: ``(resolved_destination, resolved_root)`` — the
            resolved pair the placement stages and claims under.

    Raises:
        WorkareaContainmentError: When no ``.s19tool/workarea`` anchor
            exists, when the destination or any traversed parent of it is
            a symbolic link or NTFS reparse point, when the resolved
            destination is not contained inside the resolved root, or when
            the destination cannot be resolved at all (an invalid path
            spelling raises THIS class, never a bare ``OSError`` — security
            finding SEC-2; every caller already catches the class).

    Data Flow:
        - Normalise textually (``normpath``/``abspath`` collapse ``..``
          without following a single link); locate the anchor on the
          UNRESOLVED path.
        - Walk every parent of the destination from the anchor downwards on
          the textual path, BEFORE resolving — ``Path.resolve`` silently
          follows reparse points (security finding S-N01), so a junction
          anywhere in the chain must be flagged explicitly via
          ``os.lstat`` + ``FILE_ATTRIBUTE_REPARSE_POINT``.  The walk stops
          BELOW the OUTERMOST ``.s19tool`` component (review finding N1,
          LED .50): a junction between this work area and a NESTED anchor
          lies inside the outer work area and must be checked, not skipped;
          that seam itself is checked next (a junction there is the
          executed S-02 shape — the whole work area silently resolving into
          another one).
        - Resolve BOTH sides only now and require
          :func:`contained_in_workarea` for the pair (LLR-171.4): the
          resolved bytes must land inside THIS work area.  With an
          explicit root this comparison — not the textual walk — is what
          refuses a destination that resolves into another work area
          (review finding F2).

    Dependencies:
        Uses:
            - _find_workarea_root / _find_workarea_root_shortname
            - _path_traverses_reparse_point / _is_reparse_point
            - contained_in_workarea (LLR-171.4)
        Used by:
            - place_into_workarea (LLR-163.1)
            - place_group_into_workarea (LLR-163.1, the second kind)
            - s19_app.tui.segment_split_view.write_split_join_export
              (LLR-160.2, passes its dest_dir UNRESOLVED)
            - s19_app.tui.services.project_gather_service._check_home_contained
              (LLR-171.4, the Save-project gather)
    """
    textual_destination = Path(os.path.normpath(os.path.abspath(destination)))
    if workarea_root is None:
        root = _find_workarea_root(textual_destination)
        if root is None:
            # F8's 8.3 short-name fallback: accept the non-canonical anchor
            # spellings the base accepted, per-component reparse-checked so
            # they cannot escape.
            root = _find_workarea_root_shortname(textual_destination)
        if root is None:
            raise WorkareaContainmentError(
                "Refusing to place: destination is not contained inside "
                f"<base>/{WORKAREA_DIRNAME}/{WORKAREA_SUBDIR}/: {textual_destination}"
            )
    else:
        root = Path(os.path.normpath(os.path.abspath(workarea_root)))

    if _path_traverses_reparse_point(textual_destination, stop_at=root.parent):
        raise WorkareaContainmentError(
            "Refusing to place: destination traverses a symbolic link or "
            f"reparse point: {textual_destination}"
        )
    if _is_reparse_point(root.parent):
        raise WorkareaContainmentError(
            "Refusing to place: destination traverses a symbolic link or "
            f"reparse point: {root.parent}"
        )

    try:
        resolved_destination = Path(destination).resolve()
        resolved_root = root.resolve()
    except OSError as exc:
        # security finding SEC-2: an invalid path spelling (e.g. WinError
        # 123) raises the containment refusal, never a bare OSError past
        # callers that only catch the containment class; the message leads
        # with the outcome.
        raise WorkareaContainmentError(
            "Refusing to place: destination cannot be resolved: "
            f"{textual_destination} ({exc})"
        ) from exc
    if not contained_in_workarea(resolved_destination, resolved_root):
        raise WorkareaContainmentError(
            "Refusing to place: destination is not contained inside "
            f"<base>/{WORKAREA_DIRNAME}/{WORKAREA_SUBDIR}/: {resolved_destination}"
        )
    return resolved_destination, resolved_root


def _hash_file(path: Path) -> str:
    """
    Summary:
        Return the SHA-256 hex digest of a file's bytes, read in chunks so
        large candidates never load into memory at once.

    Args:
        path (Path): An existing regular file.

    Returns:
        str: The lowercase hex digest.

    Raises:
        OSError: Propagated from reading; callers treat an unreadable file
            as untrusted.

    Data Flow:
        - Stream the file through ``hashlib.sha256`` in 64 KiB chunks.

    Dependencies:
        Uses:
            - hashlib / builtins.open
        Used by:
            - find_identical (LLR-163.1)
            - predict_placement (LLR-163.7)
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


#: A ``_<digits>`` tail between stem and suffix: the reuse-name shape
#: ``<stem>_<digits><suffix>`` (B100-I6).  Compared case-folded on Windows.
_REUSE_NUMBERED_RE = re.compile(r"^(?P<head>.+)_(?P<digits>[0-9]+)$")


def _reuse_candidate_names(listing: Sequence[str], name: str) -> list[str]:
    """
    Summary:
        Enumerate the reuse candidates for ``name`` from ONE directory
        listing (B100-I13): ``<name>`` first, then every
        ``<stem>_<digits><suffix>`` in ascending digit order.  Compared
        case-insensitively on Windows; duplicates by that comparison are
        listed once, under their on-disk spelling.

    Args:
        listing (Sequence[str]): The destination's entries (``os.listdir``).
        name (str): The requested file name.

    Returns:
        list: Candidate entry names, requested name first.

    Raises:
        None.

    Data Flow:
        - The requested name matches exactly (case-folded on Windows).
        - Any other entry whose stem is ``<stem>_<digits>`` and whose
          suffix matches (both case-folded on Windows) is numbered.
        - Numbered entries sort by their digits; ties keep listing order.

    Dependencies:
        Uses:
            - re (the numbered-tail pattern)
        Used by:
            - find_identical (LLR-163.1)
            - predict_placement (LLR-163.7)
    """
    target = Path(name)
    stem = target.stem
    suffix = target.suffix
    fold = str.casefold if sys.platform == "win32" else (lambda text: text)
    folded_name = fold(name)
    folded_stem = fold(stem)
    folded_suffix = fold(suffix)

    exact: list = []
    numbered: list = []
    seen = set()
    for entry in listing:
        entry_path = Path(entry)
        if entry_path.name != entry:
            continue  # not a plain file name; never a candidate
        if fold(entry_path.suffix) != folded_suffix:
            continue
        if fold(entry) == folded_name:
            key = fold(entry)
            if key not in seen:
                seen.add(key)
                exact.append(entry)
            continue
        match = _REUSE_NUMBERED_RE.match(entry_path.stem)
        if match is None or fold(match.group("head")) != folded_stem:
            continue
        key = fold(entry)
        if key in seen:
            continue
        seen.add(key)
        numbered.append((int(match.group("digits")), entry))
    numbered.sort(key=lambda item: item[0])
    return exact + [entry for _digits, entry in numbered]


def _match_identical(
    listing: Sequence[str],
    destination: Path,
    name: str,
    size: int,
    digest: str,
) -> Optional[Path]:
    """
    Summary:
        Return the first reuse candidate of ``destination`` that is a
        regular file, not a link or reparse point, non-empty, of ``size``
        and carrying ``digest`` — else None.  The size check runs before
        any candidate bytes are read (LLR-163.2), so only same-size
        candidates are hashed.

    Args:
        listing (Sequence[str]): ONE ``os.listdir`` of the destination.
        destination (Path): The directory the candidates live in.
        name (str): The requested file name.
        size (int): The staged size, in bytes.
        digest (str): The staged SHA-256 hex digest.

    Returns:
        Optional[Path]: The identical candidate, or None.

    Raises:
        None: an unreadable or vanishing candidate is skipped, never trusted.

    Data Flow:
        - Enumerate ``_reuse_candidate_names`` from the listing.
        - Skip links/reparse points (their bytes live outside; S-F4),
          non-regular files (directories carry no payload) and 0-byte files
          (another writer's claim placeholder; PDR C1(a)) via ``os.lstat``.
        - Compare the size first; hash only a same-size candidate.

    Dependencies:
        Uses:
            - os.lstat / stat.S_ISREG
            - _is_reparse_point / _hash_file
            - _reuse_candidate_names
        Used by:
            - find_identical (LLR-163.1)
            - predict_placement (LLR-163.7)
    """
    for entry in _reuse_candidate_names(listing, name):
        candidate = destination / entry
        if _is_reparse_point(candidate):
            continue
        try:
            candidate_stat = os.lstat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(candidate_stat.st_mode):
            continue
        if candidate_stat.st_size == 0 or candidate_stat.st_size != size:
            continue
        try:
            if _hash_file(candidate) == digest:
                return candidate
        except OSError:
            continue  # an unreadable candidate is not trusted; claim a name
    return None


def find_identical(destination: Path, name: str, staged: Path) -> Optional[Path]:
    """
    Summary:
        The ONE byte-identity rule (B100-I6 widened, B100-I13): list the
        destination once and return the first regular, non-link, non-empty,
        same-size, byte-identical file named ``<name>`` or
        ``<stem>_<digits><suffix>`` (compared case-insensitively on
        Windows), else None.

    Args:
        destination (Path): The directory to search; must exist (callers
            create it before staging).
        name (str): The requested file name.
        staged (Path): The staged payload file to compare against.

    Returns:
        Optional[Path]: The identical candidate path, or None when no
            candidate qualifies.

    Raises:
        None: a missing destination or an unreadable candidate reports None.

    Data Flow:
        - Stat and hash the staged payload once.
        - List the destination exactly once and walk
          :func:`_match_identical` over that listing — size before bytes.

    Dependencies:
        Uses:
            - os.listdir
            - _hash_file / _match_identical
        Used by:
            - place_into_workarea (LLR-163.1)
            - predict_placement (LLR-163.7)
    """
    staged = Path(staged)
    try:
        size = staged.stat().st_size
        digest = _hash_file(staged)
    except OSError:
        return None
    try:
        listing = os.listdir(destination)
    except OSError:
        return None
    return _match_identical(listing, destination, name, size, digest)


def _placed_name_candidates(name: str):
    """
    Summary:
        Yield the landing-name walk shared by the placement and its
        prediction (B100-I22): the requested name first, then the lowest
        ``_<N>`` upward.  Every yielded name is only a candidate — the
        caller decides whether the name is taken.

    Args:
        name (str): The requested file name.

    Returns:
        Iterator[str]: The requested name, then ``<stem>_1<suffix>``,
            ``<stem>_2<suffix>``, ... .

    Raises:
        None.

    Dependencies:
        Used by:
            - place_into_workarea (LLR-163.1)
            - predict_placement (LLR-163.7)
    """
    target = Path(name)
    yield target.name
    counter = 1
    while True:
        yield f"{target.stem}_{counter}{target.suffix}"
        counter += 1


def place_into_workarea(
    source: Path,
    destination: Path,
    max_size_bytes: int = DEFAULT_COPY_SIZE_CAP_BYTES,
    workarea_root: Optional[Path] = None,
) -> PlacementResult:
    """
    Summary:
        The one placement function (B100-I13): copy ``source`` into a
        workarea-contained ``destination`` — every guard, the byte-identity
        reuse decision and the landing name live HERE, and
        :func:`copy_into_workarea` is the thin ``Path``-returning wrapper.

    Args:
        source (Path): File to copy. Must be a real file (not a
            symlink/junction) and must not exceed ``max_size_bytes``.
        destination (Path): Target directory, passed UNRESOLVED — the
            guard reads the work-area root off its textual path before any
            resolution, so a pre-resolved destination would hide the
            junctions the guard exists to refuse (LLR-171.4, LED .49).
            Must name a destination inside ``<base>/.s19tool/workarea/``
            and must not traverse a symlink or NTFS junction.
        max_size_bytes (int): Maximum permitted size for ``source`` in
            bytes. Defaults to 256 MB; configurable per call to support
            regression testing (per security finding S-N02).
        workarea_root (Optional[Path]): An explicit work-area root an
            app-level caller passes when it knows THIS app's work area
            (B100-I14). None derives the root from ``destination``'s own
            textual path.

    Returns:
        PlacementResult: ``path`` is the file the placement landed on and
            ``reused`` says whether it existed before the call — a
            byte-identical target (B100-I6: the requested name or any
            ``<stem>_<N><suffix>``, case-folded on Windows, never a link,
            reparse point or 0-byte file) is reused as-is; a divergent name
            collision is resolved by claiming the next free ``_<N>`` name.

    Raises:
        WorkareaContainmentError: When ``source`` or ``destination`` (or any
            traversed parent of ``destination``) is a symbolic link or NTFS
            reparse point, when ``destination`` is not contained inside this
            work area, or when ``source`` exceeds ``max_size_bytes``.
        FileNotFoundError: When ``source`` does not exist.
        WorkareaPlacementError: When the staged copy fails with an
            ``OSError`` (e.g. the source vanishing after the size check —
            security finding S-F6), when the claimed name cannot be filled
            within 5 retries in 1 s (a locked target), when the claim or
            the fill fails with any other ``OSError``, or when the claim
            cannot be verified as a regular file after the open (security
            finding S-F1) — never an uncaught ``OSError`` past callers that
            only catch the containment class (review finding F1). Subclass
            of ``WorkareaContainmentError``; the message leads with the
            outcome and names the file and the next step (LLR-155.2).

    Data Flow:
        - Reject reparse-point sources directly; reject when the resolved
          source is one either (before resolving, which would follow them).
        - Run the ONE shared destination guard
          (:func:`_guarded_destination`, LLR-171.4, LED .49): the
          work-area root is taken from ``destination`` AS GIVEN — the
          OUTERMOST textual ``.s19tool/workarea`` ancestor (review finding
          N1, LED .50; case-folded on
          Windows, with an 8.3 short-name fallback for non-canonical
          spellings) or the explicit root the caller passes — the reparse
          walk runs on the unresolved path BEFORE any resolution
          (``Path.resolve`` silently follows junctions, security finding
          S-N01; the executed S-02 probe wrote into another work area
          through a junction this walk now refuses), and only then are the
          destination and the root resolved and compared
          (:func:`contained_in_workarea`): the resolved bytes must land
          inside THIS work area.
        - Enforce ``max_size_bytes`` on ``source.stat().st_size``
          (security finding S-N03) BEFORE any staging, so a refused
          placement writes nothing at all.
        - Stage privately (LLR-155.1) via :func:`_private_stage_dir`: both
          ``temp`` and ``temp/.staging`` reparse-checked, then copy the
          source into a ``tempfile.mkdtemp`` directory under
          ``temp/.staging/`` — the source is only read, never moved,
          renamed or deleted.
        - Reuse: :func:`find_identical` decides on the ONE listing of the
          destination; race-freeness rests on the immutability invariant
          (LLR-155.3 as amended by LED .7) — no in-app writer replaces or
          deletes a placed file — not on a narrower check window.
          Since security finding SEC2-7 (round 4) this rule is the ONLY
          byte-identity judge: the project gather places through this
          function and translates only the ``reused`` flag — its former
          sibling byte-scan is retired, so no second rule can disagree
          with this one (the TC-B100-57 census).  A reused
          placement returns the existing path with ``reused=True`` and
          writes nothing.
        - Otherwise claim the first free candidate name from
          :func:`_placed_name_candidates` — a name taken by ANY type —
          file, directory, link, dangling link or junction — counts as
          taken on every platform, because on Windows a bare ``O_EXCL``
          open FOLLOWS a dangling symlink and would create the claim at the
          link's target outside the work area (security finding S-F1;
          review finding F1). The claim is re-verified with ``os.lstat``
          to be a regular file and no reparse point, and filled with
          ``os.replace``, retrying a ``PermissionError`` up to 5 times
          within 1 s before removing the own claim and raising
          ``WorkareaPlacementError``.
        - Remove the own staging directory in a ``finally`` tracked by an
          ownership flag set right after ``mkdtemp``.

    Dependencies:
        Uses:
            - shutil.copy2 / shutil.rmtree
            - tempfile.mkdtemp
            - os.open / os.replace / os.unlink / os.lstat
            - _is_reparse_point
            - _guarded_destination (the one destination guard, LLR-171.4)
            - contained_in_workarea (LLR-171.4)
            - find_identical / _placed_name_candidates
        Used by:
            - copy_into_workarea (the one-line wrapper, B100-I13)
            - s19_app.tui.app.S19TuiApp._sync_loaded_file_to_project
              (LLR-163.5)
            - predict_placement shares the candidate and name walks
              (LLR-163.7)
    """
    # Reject symlinks/junctions on the source side before resolving (which would follow them).
    if _is_reparse_point(source):
        raise WorkareaContainmentError(
            f"Refusing to copy: source is a symbolic link or reparse point: {source}"
        )

    resolved_source = source.resolve()
    if _is_reparse_point(resolved_source):
        raise WorkareaContainmentError(
            f"Refusing to copy: resolved source is a symbolic link or reparse point: {resolved_source}"
        )

    # The ONE destination guard (LLR-171.4, LED .49, review finding F1):
    # runs on the destination AS GIVEN, before any resolution — a caller
    # that pre-resolves hides the junctions this guard exists to refuse
    # (the executed S-02 probe).  The work-area root is the OUTERMOST
    # textual ``.s19tool/workarea`` ancestor (review finding N1, LED .50)
    # or the explicit root an app-level caller passes; both sides are
    # resolved and compared only afterwards.
    resolved_destination, resolved_root = _guarded_destination(
        destination, workarea_root
    )

    size = resolved_source.stat().st_size
    if size > max_size_bytes:
        raise WorkareaContainmentError(
            f"Refusing to copy: source size {size} bytes exceeds cap {max_size_bytes} bytes: {resolved_source}"
        )

    try:
        resolved_destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # security finding SEC-2: an invalid path spelling (WinError 123)
        # raises the containment refusal, never a bare OSError past callers
        # that only catch the containment class; the message leads with the
        # outcome.  (On Python 3.12 the guard's resolve() raises first; on
        # 3.11 non-strict resolve normalizes textually and the creation is
        # the first filesystem touch.)
        raise WorkareaContainmentError(
            "Refusing to place: destination cannot be created: "
            f"{resolved_destination} ({exc})"
        ) from exc

    # Private staging (LLR-155.1): the reparse-checked shared staging home,
    # factored into one helper so every work-area writer stages the same way.
    stage_dir = _private_stage_dir(resolved_root)
    staging_owned = True
    try:
        staged_file = stage_dir / resolved_source.name
        try:
            shutil.copy2(resolved_source, staged_file)
        except OSError as exc:
            # security finding S-F6: an OSError from the copy — e.g. the
            # source vanishing after the size check — is a placement
            # failure, never an uncaught OSError past callers that only
            # catch the containment class; outcome first, naming the source
            raise WorkareaPlacementError(
                f"Not saved: {resolved_source.name} could not be copied: "
                f"{exc}. Nothing written."
            ) from exc

        # Byte-identity reuse (B100-I6 widened, LLR-163.1): ONE listing of
        # the destination decides — the requested name and every
        # <stem>_<N><suffix>, size checked before any candidate bytes are
        # read (LLR-163.2). Race-freeness rests on the immutability
        # invariant (LLR-155.3), not on a narrower check window.
        identical = find_identical(
            resolved_destination, resolved_source.name, staged_file
        )
        if identical is not None:
            return PlacementResult(identical, reused=True)

        # Exclusive, atomic placement (LLR-155.2): claim the first free
        # candidate name with O_CREAT|O_EXCL and fill the claim with
        # os.replace. The source is only ever read, never moved, renamed or
        # deleted.
        claim_path: Optional[Path] = None
        claim_owned = False
        for candidate_name in _placed_name_candidates(resolved_source.name):
            candidate = resolved_destination / candidate_name
            # Security finding S-F1: lstat the candidate BEFORE the O_EXCL
            # claim. On Windows, os.open(O_CREAT|O_EXCL) FOLLOWS a dangling
            # symlink: the claim would create a 0-byte file at the link's
            # target OUTSIDE the work area and os.replace would then
            # replace the link. ANY existing entry — file, directory, link,
            # dangling link or junction — is taken.
            try:
                os.lstat(candidate)
            except OSError:
                pass  # the name is free
            else:
                continue
            claim_path = candidate
            try:
                claim_fd = os.open(
                    str(claim_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                )
                claim_owned = True
            except FileExistsError:
                # lost a lstat-vs-open race: the name is taken after all
                claim_path = None
                continue
            except OSError as exc:
                # any other claim failure is a placement failure, never an
                # uncaught OSError past callers that only catch the
                # containment class (review finding F1); if the name exists
                # after all (a lstat-vs-open race that surfaced late, e.g.
                # a directory on Windows raising PermissionError) it is
                # simply taken — move on to the next ``_<N>``
                try:
                    os.lstat(claim_path)
                except OSError:
                    raise WorkareaPlacementError(
                        f"Not saved: {claim_path.name} in {resolved_destination} "
                        f"could not be claimed: {exc}. Nothing written."
                    ) from exc
                claim_path = None
                continue
            os.close(claim_fd)
            # Security finding S-F1: re-verify the claim is a regular file
            # this call just created — not a reparse point swapped in after
            # the pre-claim lstat — else remove the claim and refuse.
            try:
                claim_stat = os.lstat(claim_path)
            except OSError as exc:
                if claim_owned:
                    try:
                        os.unlink(claim_path)
                    except OSError:
                        pass
                raise WorkareaPlacementError(
                    f"Not saved: {claim_path.name} in {resolved_destination} "
                    f"could not be verified after the claim: {exc}. "
                    "Nothing written."
                ) from exc
            if not stat.S_ISREG(claim_stat.st_mode) or _is_reparse_point(claim_path):
                if claim_owned:
                    try:
                        os.unlink(claim_path)
                    except OSError:
                        pass
                raise WorkareaPlacementError(
                    f"Not saved: {claim_path.name} in {resolved_destination} "
                    "was replaced by a link or special file between the claim "
                    "and the write. Nothing written."
                )
            break

        # The name walk is unbounded (``_<N>`` for every N), so the loop
        # always breaks with a claim; ``claim_path`` is bound here.

        deadline = time.monotonic() + 1.0
        attempts = 0
        while True:
            try:
                os.replace(staged_file, claim_path)
                break
            except PermissionError:
                attempts += 1
                if attempts >= 5 or time.monotonic() >= deadline:
                    if claim_owned:
                        try:
                            os.unlink(claim_path)
                        except OSError:
                            pass
                    raise WorkareaPlacementError(
                        f"Not saved: {claim_path.name} in {resolved_destination} "
                        "is still locked after 5 retries, another program may "
                        "hold it — close it and retry. Nothing written."
                    ) from None
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            except OSError as exc:
                # any other fill failure (e.g. a cross-device replace) fails
                # the write outright — never a fallback to a move or a
                # copy-then-delete of the source (LLR-155.2), and never an
                # uncaught OSError past callers that only catch the
                # containment class (review finding F1)
                if claim_owned:
                    try:
                        os.unlink(claim_path)
                    except OSError:
                        pass
                raise WorkareaPlacementError(
                    f"Not saved: {claim_path.name} in {resolved_destination} "
                    f"could not be written: {exc}. Nothing written."
                ) from exc
        return PlacementResult(claim_path, reused=False)
    finally:
        # only ever the staging this call created (LLR-155.1/155.7)
        if staging_owned:
            shutil.rmtree(stage_dir, ignore_errors=True)


def predict_placement(
    digest_or_bytes: "str | bytes",
    size: int,
    destination: Path,
    name: str,
) -> PlacementResult:
    """
    Summary:
        Answer, WITHOUT writing, where :func:`place_into_workarea` would
        land a file of this digest (or these bytes) and size (B100-I22,
        LLR-163.7): the same candidate walk (``find_identical``'s rule) and
        the same free-name walk (:func:`_placed_name_candidates`), so the
        save plan's prediction and the placement are one rule.

    Args:
        digest_or_bytes: The payload's SHA-256 hex digest (str) or the
            payload bytes themselves (bytes-like; hashed here, never held
            in memory by the planner).
        size (int): The payload size, in bytes. Candidates are compared by
            size first, then by digest.
        destination (Path): The target directory the placement would use.
        name (str): The requested file name.

    Returns:
        PlacementResult: The predicted landing path — in the SAME resolved
            path FORM :func:`place_into_workarea` returns (review finding
            F4), so a relative or non-canonical destination cannot produce
            a false prediction/placement mismatch — and whether the
            placement would reuse an existing file. Nothing is created,
            claimed, staged or written.

    Raises:
        None: a missing destination predicts a fresh placement under the
            requested name.

    Data Flow:
        - Normalise the digest (hash ``bytes`` input in one pass).
        - List the destination once and run the shared
          :func:`_match_identical` candidate walk (size before digest).
        - On a match, predict that path with ``reused=True``; otherwise
          predict the first candidate name free per ``os.lstat`` —
          directories and links occupy a name exactly as they do for the
          placement's O_EXCL claim.
        - A concurrent claim can still make the prediction and the
          placement diverge; the save-plan handler reports that mismatch
          naming both paths (B100-I17).

    Dependencies:
        Uses:
            - hashlib / os.listdir / os.lstat
            - _match_identical / _placed_name_candidates
        Used by:
            - plan_project_save (B100-I17, LLR-167.6)
    """
    if isinstance(digest_or_bytes, str):
        digest = digest_or_bytes
    else:
        digest = hashlib.sha256(bytes(digest_or_bytes)).hexdigest()

    destination = Path(destination).resolve()
    target_name = Path(name).name
    try:
        listing = os.listdir(destination)
    except OSError:
        listing = []

    identical = _match_identical(listing, destination, target_name, size, digest)
    if identical is not None:
        return PlacementResult(identical, reused=True)

    for candidate_name in _placed_name_candidates(target_name):
        try:
            os.lstat(destination / candidate_name)
        except OSError:
            return PlacementResult(destination / candidate_name, reused=False)
    raise AssertionError("unreachable: the name walk is unbounded")  # pragma: no cover


def copy_into_workarea(
    source: Path,
    destination: Path,
    max_size_bytes: int = DEFAULT_COPY_SIZE_CAP_BYTES,
    workarea_root: Optional[Path] = None,
) -> Path:
    """
    Summary:
        Copy ``source`` into a workarea-contained ``destination`` — the
        one-line wrapper over :func:`place_into_workarea` (B100-I13,
        LLR-163.1): every guard — the source and destination reparse
        checks, this-work-area containment on the UNRESOLVED destination
        (LLR-171.4, ``_guarded_destination``, LED .49), the size cap,
        private staging, the byte-identity reuse (:func:`find_identical`,
        B100-I6) and the ``O_EXCL`` claim of the lowest free ``_<N>`` —
        lives in the placement function, so all 15 call sites in 7 files
        (P-34) keep their ``Path`` return and are covered by construction.

    Args:
        source (Path): File to copy; must be a real file within the size
            cap (see :func:`place_into_workarea`).
        destination (Path): Target directory, passed UNRESOLVED; the guard
            reads the work-area root off its textual path before any
            resolution (LLR-171.4, LED .49).
        max_size_bytes (int): Maximum permitted size for ``source`` in
            bytes; defaults to 256 MB.
        workarea_root (Optional[Path]): An explicit work-area root an
            app-level caller passes when it knows THIS app's work area
            (B100-I14, security finding SEC-1, LED .50). None derives the
            root from ``destination``'s own textual path.

    Returns:
        Path: The file the placement landed on — the requested name, an
            identical file reused as-is, or the claimed lowest free
            ``_<N>``.

    Raises:
        WorkareaContainmentError: When ``source`` or ``destination``
            (or any traversed parent of it) is a symbolic link or NTFS
            reparse point, when ``destination`` is not contained inside
            this work area, or when ``source`` exceeds ``max_size_bytes``.
        FileNotFoundError: When ``source`` does not exist.
        WorkareaPlacementError: When the staged copy, the claim or the
            fill fails (see :func:`place_into_workarea`).

    Data Flow:
        - Exactly ``return place_into_workarea(...).path`` — one
          statement, so no guard and no second claim loop can live here
          (the TC-B100-01 AST arm pins this shape).

    Dependencies:
        Uses:
            - place_into_workarea (the one placement function, LLR-163.1)
        Used by:
            - 15 call sites in 7 product files (P-34), unchanged
    """
    return place_into_workarea(
        source, destination, max_size_bytes, workarea_root
    ).path


def place_group_into_workarea(
    sources: Sequence[Path],
    destination: Path,
    *,
    max_size_bytes: Optional[int] = None,
    workarea_root: Optional[Path] = None,
) -> list[Path]:
    """
    Summary:
        Place a GROUP of files that must share ONE ``_<N>`` suffix — a BIN
        and its ``.addr`` sidecar (B99-I2a, LLR-160.4) — into a
        workarea-contained ``destination``, enforcing the
        :func:`copy_into_workarea` containment, reparse-point and size
        guards on every member. One private staging directory hosts the
        copies; one ``_<N>`` is claimed for EVERY name of the group with
        ``O_EXCL`` before any member is written; each claim is then filled
        by ``os.replace``. Per-file placement cannot be used here: two
        independent claims can land on different suffixes and split the
        pair (a mixed ``_<N>`` BIN/``.addr`` pair), which this call refuses
        by construction.

    Args:
        sources (Sequence[Path]): The group's source files, in order. Each
            must be a real file (not a symlink/junction) within the size
            cap; the final name of each member is its own file name.
        destination (Path): Target directory, passed UNRESOLVED — the
            shared guard reads the work-area root off its textual path
            before any resolution. Must name a directory inside
            ``<base>/.s19tool/workarea/`` and must not traverse a symlink
            or NTFS junction.
        max_size_bytes (Optional[int]): Maximum permitted size per member,
            in bytes. ``None`` (the default) applies
            :data:`DEFAULT_COPY_SIZE_CAP_BYTES`, matching
            :func:`copy_into_workarea`.
        workarea_root (Optional[Path]): An explicit work-area root an
            app-level caller passes when it knows THIS app's work area
            (B100-I14, security finding SEC-1, LED .50). None derives the
            root from ``destination``'s own textual path.

    Returns:
        list[Path]: The placed paths, aligned with ``sources``. When every
            requested name already holds a non-empty byte-identical file,
            the whole group is REUSED and the existing paths are returned —
            reuse never fires per member (a half-identical group claims a
            fresh shared suffix).

    Raises:
        WorkareaContainmentError: When ``destination`` is not contained
            inside a ``.s19tool/workarea/`` root, when any member source or
            any traversed parent of ``destination`` is a symbolic link or
            NTFS reparse point, or when a member exceeds the size cap.
        FileNotFoundError: When a member source does not exist.
        WorkareaPlacementError: On any failure after staging — a duplicate
            member name, a staging copy failure (security finding S-F6), a
            claim that cannot be verified as a regular file (security
            finding S-F1), a fill that stays locked after 5 retries within
            1 s, or any other fill ``OSError``. Every own claim and placed
            file is rolled back first: no orphan member, no 0-byte claim,
            and the message leads with the outcome (LLR-160.5's part-way
            contract; PDR C3(c)).

    Data Flow:
        - Run the shared destination guard :func:`_guarded_destination` on
          the UNRESOLVED ``destination`` (LLR-163.1, LED .49) — the same
          checks :func:`place_into_workarea` runs (LLR-171.4, LLR-155's
          seam, C3(e)).
        - Validate every member (reparse + size), reject duplicate member
          names, and create the destination on demand.
        - Stage privately (LLR-155.1) via :func:`_private_stage_dir` —
          the sources are only read, never moved, renamed or deleted.
        - Group reuse (bug B8 at the requested names only): every target
          must exist, be non-empty (PDR C1(a) — a 0-byte target may be
          another writer's claim placeholder) and byte-identical; a link
          or reparse target is never reused (security finding S-F4).
        - Otherwise claim the smallest ``_<N>`` whose candidate names are
          ALL free (an lstat first — security finding S-F1: ANY existing
          entry counts as taken), releasing a partially claimed suffix
          before trying the next one; verify each claim with lstat as a
          regular file and no reparse point.
        - Fill each claim with ``os.replace``, retrying a
          ``PermissionError`` up to 5 times within 1 s; on any failure
          roll back EVERY own claim (placed or still an empty claim) and
          raise :class:`WorkareaPlacementError`.
        - Remove the own staging directory in a ``finally`` tracked by an
          ownership flag set right after ``_private_stage_dir``.

    Dependencies:
        Uses:
            - shutil.copy2 / shutil.rmtree
            - tempfile (via _private_stage_dir)
            - os.open / os.replace / os.unlink / os.lstat
            - _is_reparse_point
            - _guarded_destination (the one destination guard, LLR-171.4)
            - _private_stage_dir
        Used by:
            - s19_app.tui.segment_split_view.write_split_join_export
              (the BIN/``.addr`` pair; single files ride
              :func:`copy_into_workarea`)
    """
    # The ONE shared destination guard (LLR-163.1 as amended by LED .49,
    # review finding F1) — the same check place_into_workarea runs, on the
    # UNRESOLVED destination: the root comes off the textual path (the
    # OUTERMOST anchor, review finding N1, LED .50), the reparse walk runs
    # before any resolution, and only then are the two sides resolved and
    # compared (LLR-171.4).  The explicit root an app-level caller passes
    # (security finding SEC-1) rides through as the containment authority.
    resolved_destination, group_root = _guarded_destination(
        destination, workarea_root
    )

    cap = DEFAULT_COPY_SIZE_CAP_BYTES if max_size_bytes is None else max_size_bytes
    resolved_sources: list[Path] = []
    for source in sources:
        source = Path(source)
        if _is_reparse_point(source):
            raise WorkareaContainmentError(
                "Refusing to place: source is a symbolic link or reparse point: "
                f"{source}"
            )
        resolved_source = source.resolve()
        if _is_reparse_point(resolved_source):
            raise WorkareaContainmentError(
                "Refusing to place: resolved source is a symbolic link or reparse "
                f"point: {resolved_source}"
            )
        size = resolved_source.stat().st_size
        if size > cap:
            raise WorkareaContainmentError(
                f"Refusing to place: source size {size} bytes exceeds cap "
                f"{cap} bytes: {resolved_source}"
            )
        resolved_sources.append(resolved_source)

    if len({src.name for src in resolved_sources}) != len(resolved_sources):
        raise WorkareaPlacementError(
            "Not saved: the group carries a duplicate file name — the members "
            "would claim one final name. Nothing written."
        )

    try:
        resolved_destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # security finding SEC-2: an invalid path spelling (WinError 123)
        # raises the containment refusal, never a bare OSError past callers
        # that only catch the containment class; the message leads with the
        # outcome.
        raise WorkareaContainmentError(
            "Refusing to place: destination cannot be created: "
            f"{resolved_destination} ({exc})"
        ) from exc

    # Private staging (LLR-155.1): the same reparse-checked staging home
    # copy_into_workarea stages under.
    stage_dir = _private_stage_dir(group_root)
    staging_owned = True
    try:
        staged: list[tuple[Path, bytes]] = []
        for resolved_source in resolved_sources:
            staged_file = stage_dir / resolved_source.name
            try:
                shutil.copy2(resolved_source, staged_file)
            except OSError as exc:
                # security finding S-F6: an OSError from the copy — e.g. the
                # source vanishing after the size check — is a placement
                # failure, never an uncaught OSError past callers that only
                # catch the containment class; outcome first
                raise WorkareaPlacementError(
                    f"Not saved: {resolved_source.name} could not be copied: "
                    f"{exc}. Nothing written."
                ) from exc
            staged.append((staged_file, staged_file.read_bytes()))

        # Group reuse (bug B8 at the requested names ONLY, C3(e)): the group
        # is reused only when EVERY target exists, is non-empty (PDR C1(a) —
        # a 0-byte target may be another writer's claim placeholder) and is
        # byte-identical to its staged member; a link or reparse target is
        # never reused — its bytes live outside the work area (S-F4).
        targets = [resolved_destination / src.name for src in resolved_sources]
        try:
            if all(
                (not _is_reparse_point(t)) and t.exists() and t.stat().st_size > 0
                for t in targets
            ) and all(
                t.read_bytes() == staged[i][1] for i, t in enumerate(targets)
            ):
                return list(targets)
        except OSError:
            # an unreadable target is not trusted; claim fresh names
            pass

        # Claim ONE ``_<N>`` for EVERY name of the group before any member
        # is written: the smallest suffix whose candidate names are ALL
        # free — a half-taken suffix is released and skipped as a whole, so
        # the pair can never split.
        claims: list[Path] = []
        claims_owned = False
        counter = 0
        while len(claims) < len(staged):
            if counter == 0:
                candidates = targets
            else:
                candidates = [
                    resolved_destination / f"{src.stem}_{counter}{src.suffix}"
                    for src in resolved_sources
                ]
            counter += 1
            taken = False
            for candidate in candidates:
                # Security finding S-F1: lstat the candidate BEFORE the
                # O_EXCL claim. On Windows, os.open(O_CREAT|O_EXCL) FOLLOWS
                # a dangling symlink: the claim would create a 0-byte file
                # at the link's target OUTSIDE the work area. ANY existing
                # entry — file, directory, link, dangling link or junction —
                # is taken.
                try:
                    os.lstat(candidate)
                except OSError:
                    continue  # the name is free
                taken = True
                break
            if taken:
                continue
            for candidate in candidates:
                claim_path = candidate
                try:
                    claim_fd = os.open(
                        str(claim_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                    )
                    claims_owned = True
                except FileExistsError:
                    # lost a lstat-vs-open race: release the partial set
                    # and take the next ``_<N>`` as a whole
                    for claim_path in claims:
                        if claims_owned:
                            try:
                                os.unlink(claim_path)
                            except OSError:
                                pass
                    claims.clear()
                    taken = True
                    break
                except OSError as exc:
                    # any other claim failure is a placement failure; when
                    # the name exists after all (a race that surfaced late)
                    # it is simply taken — release and move on. ``failed_path``
                    # pins the name this claim was trying: the rollback loop
                    # below rebinds ``claim_path``.
                    failed_path = claim_path
                    try:
                        os.lstat(claim_path)
                    except OSError:
                        if claims_owned:
                            for claim_path in claims:
                                try:
                                    os.unlink(claim_path)
                                except OSError:
                                    pass
                        raise WorkareaPlacementError(
                            f"Not saved: {failed_path.name} in {resolved_destination} "
                            f"could not be claimed: {exc}. Nothing written."
                        ) from exc
                    for claim_path in claims:
                        if claims_owned:
                            try:
                                os.unlink(claim_path)
                            except OSError:
                                pass
                    claims.clear()
                    taken = True
                    break
                os.close(claim_fd)
                # Security finding S-F1: re-verify the claim is a regular
                # file this call just created — not a reparse point swapped
                # in after the pre-claim lstat.
                claim_stat = os.lstat(claim_path)
                if not stat.S_ISREG(claim_stat.st_mode) or _is_reparse_point(
                    claim_path
                ):
                    # ``failed_path`` pins the swapped claim: the rollback
                    # loop below rebinds ``claim_path``.
                    failed_path = claim_path
                    if claims_owned:
                        try:
                            os.unlink(claim_path)
                        except OSError:
                            pass
                    for claim_path in claims:
                        if claims_owned:
                            try:
                                os.unlink(claim_path)
                            except OSError:
                                pass
                    raise WorkareaPlacementError(
                        f"Not saved: {failed_path.name} in {resolved_destination} "
                        "was replaced by a link or special file between the claim "
                        "and the write. Nothing written."
                    )
                claims.append(claim_path)
            if taken:
                continue

        # Fill each claim from its staged member. On ANY failure roll back
        # EVERY own claim — placed or still an empty claim — so no orphan
        # member and no 0-byte claim survives (PDR C3(c)).
        for index, (staged_file, _payload) in enumerate(staged):
            claim_path = claims[index]
            # ``failed_path`` pins the member whose fill fails: the rollback
            # loops below rebind ``claim_path`` to the group's last claim.
            failed_path = claim_path
            deadline = time.monotonic() + 1.0
            attempts = 0
            while True:
                try:
                    os.replace(staged_file, claim_path)
                    break
                except PermissionError:
                    attempts += 1
                    if attempts >= 5 or time.monotonic() >= deadline:
                        for claim_path in claims:
                            if claims_owned:
                                try:
                                    os.unlink(claim_path)
                                except OSError:
                                    pass
                        raise WorkareaPlacementError(
                            f"Not saved: {failed_path.name} in {resolved_destination} "
                            "is still locked after 5 retries, another program may "
                            "hold it — close it and retry. Nothing written."
                        ) from None
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                except OSError as exc:
                    # any other fill failure fails the whole group —
                    # never a fallback to a copy-then-delete of the source
                    for claim_path in claims:
                        if claims_owned:
                            try:
                                os.unlink(claim_path)
                            except OSError:
                                pass
                    raise WorkareaPlacementError(
                        f"Not saved: {failed_path.name} in {resolved_destination} "
                        f"could not be written: {exc}. Nothing written."
                    ) from exc
        return claims
    finally:
        # only ever the staging this call created (LLR-155.1/155.7)
        if staging_owned:
            shutil.rmtree(stage_dir, ignore_errors=True)


def is_windows_device_name(name: str) -> bool:
    """
    Summary:
        The one shared Windows device-name predicate (HLR-164 / LLR-164.1,
        B-12 — later reused by LLR-169.8 and LLR-172.2): true when ``name``
        is a reserved device name — ``CON``, ``PRN``, ``AUX``, ``NUL``,
        ``COM0``-``COM9``, ``LPT0``-``LPT9``, ``CONIN$`` / ``CONOUT$`` —
        compared case-folded, with or without an extension (``con.txt``)
        or a superscript digit (``LPT¹``). Windows matches the part of
        the name before the FIRST dot, ignoring trailing spaces and dots,
        so ``NUL.tar.gz`` names ``NUL`` (review finding F3 / SEC2-2).

    Args:
        name (str): The name to check — the raw typed name, the sanitised
            name or one path component of either.

    Returns:
        bool: True when the name's stem (the part before the first dot,
            trailing spaces and dots stripped) is a reserved device name.
    """
    if not name:
        return False
    folded = name.translate(_DEVICE_DIGIT_TRANSLATION).casefold()
    stem = folded.partition(".")[0].rstrip(" .")
    if stem in _WINDOWS_DEVICE_BASES:
        return True
    return (
        len(stem) == 4
        and stem[:3] in {"com", "lpt"}
        and stem[3] in "0123456789"
    )


def sanitize_project_name(name: str) -> Optional[str]:
    """Return a filesystem-safe project name or None if empty after cleaning."""
    cleaned = "".join(ch for ch in name.strip() if ch.isalnum() or ch in {"-", "_"})
    return cleaned if cleaned else None


def validate_project_files(project_dir: Path) -> tuple[list[Path], list[Path], Optional[str]]:
    """
    Summary:
        Scan ``project_dir`` and return its data/A2L files, enforcing the
        project cardinality rules: any number of S19/HEX variants
        (multi-variant model, LLR-005.1), at most one MAC, at most one A2L.

    Args:
        project_dir (Path): Project directory to scan. Only direct children
            that are regular files are considered; subdirectories (e.g. a
            ``reports/`` output folder, LLR-007.7) are skipped.

    Returns:
        tuple[list[Path], list[Path], Optional[str]]: ``(data_files,
            a2l_files, error_message)``. ``data_files`` holds S19/HEX/MAC
            entries sorted by ``(name.lower(), name)`` so variant order is
            deterministic across operating systems; ``a2l_files`` holds A2L
            entries; ``error_message`` is ``None`` when the rules hold.

    Data Flow:
        - Iterate direct children, skipping non-files.
        - Bucket by suffix into data (primary S19/HEX vs MAC) and A2L lists.
        - Reject >1 MAC or >1 A2L; multiple S19/HEX files are accepted as
          project variants.
        - Sort ``data_files`` deterministically before returning.

    Dependencies:
        Uses:
            - PROJECT_DATA_EXTENSIONS / PROJECT_PRIMARY_DATA_EXTENSIONS /
              MAC_EXTENSIONS / A2L_EXTENSIONS
        Used by:
            - s19_app.tui.app.S19TuiApp (save/load/sync project paths)
            - build_variant_set callers (variant selector, E5b/E6)
    """
    data_files = []
    mac_files = []
    a2l_files = []
    for item in project_dir.iterdir():
        if not item.is_file():
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


def build_variant_set(
    project_name: str,
    data_files: Sequence[Path],
    active_id: Optional[str] = None,
) -> ProjectVariantSet:
    """
    Summary:
        Build the ``ProjectVariantSet`` for a project from the data files
        returned by ``validate_project_files``, keeping only S19/HEX images
        as variants (MAC files are overlays, not variants).

    Args:
        project_name (str): Name of the project the variants belong to.
        data_files (Sequence[Path]): Data files of the project, typically the
            first element of the ``validate_project_files`` return. Non-primary
            entries (e.g. ``.mac``) are ignored.
        active_id (Optional[str]): Variant to mark active. Defaults to the
            first variant in deterministic order, or ``None`` when the project
            has no variants.

    Returns:
        ProjectVariantSet: Variants ordered by ``(name.lower(), name)`` with
            ``active_id`` resolved per the rule above. The ``variant_id`` is
            the filename stem, EXCEPT when two or more variants share a stem
            (e.g. ``fw.s19`` + ``fw.hex``): every colliding variant's id is
            then its FULL FILENAME — deterministic and consistent with the
            E5b display fallback (the operator-ratified E6 duplicate-id
            decision).

    Raises:
        ValueError: When ``active_id`` is given but does not match any
            variant id (e.g. a stale manifest override, LLR-006.1).

    Data Flow:
        - Filter ``data_files`` to S19/HEX suffixes.
        - Sort by ``(name.lower(), name)`` (LLR-005.1 order) and wrap each
          path in a ``VariantDescriptor`` — ``variant_id`` is the stem, or
          the full filename when the stem collides with another variant.
        - Resolve ``active_id``: explicit value validated against the variant
          ids, otherwise first variant (or ``None`` when empty).

    Dependencies:
        Uses:
            - s19_app.tui.models.VariantDescriptor / ProjectVariantSet
            - S19_EXTENSIONS / PROJECT_PRIMARY_DATA_EXTENSIONS
        Used by:
            - Variant selector and execution layers (E5b/E6 consumers)

    Example:
        >>> vset = build_variant_set("proj", [Path("b.s19"), Path("a.s19")])
        >>> [v.variant_id for v in vset.variants]
        ['a', 'b']
        >>> vset.active_id
        'a'
    """
    primaries = sorted(
        (item for item in data_files if item.suffix.lower() in PROJECT_PRIMARY_DATA_EXTENSIONS),
        key=lambda item: (item.name.lower(), item.name),
    )
    stem_counts = Counter(item.stem for item in primaries)
    variants = tuple(
        VariantDescriptor(
            variant_id=item.name if stem_counts[item.stem] > 1 else item.stem,
            path=item,
            file_type="s19" if item.suffix.lower() in S19_EXTENSIONS else "hex",
        )
        for item in primaries
    )
    if active_id is None:
        resolved_active = variants[0].variant_id if variants else None
    else:
        if active_id not in {variant.variant_id for variant in variants}:
            raise ValueError(f"active_id {active_id!r} does not match any project variant")
        resolved_active = active_id
    return ProjectVariantSet(
        project_name=project_name,
        variants=variants,
        active_id=resolved_active,
    )


def find_repo_root(start: Path) -> Optional[Path]:
    """Find the nearest parent directory containing pyproject.toml or project.toml."""
    current = start.resolve()
    for _ in range(6):
        if (current / "pyproject.toml").exists() or (current / "project.toml").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def resolve_input_path(raw_path: Path, base_dir: Path) -> Optional[Path]:
    """Resolve a path against the base directory and repository root."""
    candidate = Path(str(raw_path).strip().strip('"')).expanduser()
    if candidate.exists():
        return candidate
    if not candidate.is_absolute():
        base_candidate = (base_dir / candidate).resolve()
        if base_candidate.exists():
            return base_candidate
        repo_root = find_repo_root(base_dir)
        if repo_root:
            repo_candidate = (repo_root / candidate).resolve()
            if repo_candidate.exists():
                return repo_candidate
    return None
