from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Sequence

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
        Return the ``<base>/.s19tool/workarea`` ancestor of ``destination`` if one exists.

    Args:
        destination (Path): Resolved destination directory.

    Returns:
        Optional[Path]: The first ancestor (or self) that ends with ``.s19tool/workarea``,
            or None when no such ancestor exists.

    Raises:
        None.

    Data Flow:
        - Walk ``destination`` and each parent looking for the parts pair
          (``.s19tool``, ``workarea``).
        - Return the matching ancestor whose final two parts are that pair.

    Dependencies:
        Uses:
            - pathlib.Path
        Used by:
            - copy_into_workarea
    """
    candidate = destination
    while True:
        parts = candidate.parts
        if len(parts) >= 2 and parts[-2] == WORKAREA_DIRNAME and parts[-1] == WORKAREA_SUBDIR:
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


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


def copy_into_workarea(
    source: Path,
    destination: Path,
    max_size_bytes: int = DEFAULT_COPY_SIZE_CAP_BYTES,
) -> Path:
    """
    Summary:
        Copy ``source`` into a workarea-contained ``destination`` after enforcing
        containment, reparse-point, and size guards.

    Args:
        source (Path): File to copy. Must be a real file (not a symlink/junction) and
            must not exceed ``max_size_bytes``.
        destination (Path): Target directory. Must resolve under
            ``<base>/.s19tool/workarea/`` and must not traverse a symlink or NTFS junction.
        max_size_bytes (int): Maximum permitted size for ``source`` in bytes. Defaults to
            256 MB; configurable per call to support regression testing (per security
            finding S-N02).

    Returns:
        Path: Absolute path of the file written inside ``destination``. A
            byte-identical target is reused as-is (bug B8 content dedup,
            never of a 0-byte target); a divergent name collision is
            resolved by claiming the next free ``_<N>`` name.

    Raises:
        WorkareaContainmentError: When ``destination`` is not contained inside a
            ``.s19tool/workarea/`` root, when ``source`` or ``destination`` (or any traversed
            parent of ``destination``) is a symbolic link or NTFS reparse point, or when
            ``source`` exceeds ``max_size_bytes``. Closes Phase 2 blockers S-001, S-002.
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
        - Resolve ``source`` and ``destination`` to absolute paths.
        - Reject reparse-point sources directly; reject when the destination, or any
          parent of the destination up to its workarea root, is a reparse point. ``Path.resolve``
          alone is not sufficient on Windows (per security finding S-N01).
        - Locate the ``.s19tool/workarea`` ancestor of ``destination``; reject when missing
          (closes blocker S-001).
        - Enforce ``max_size_bytes`` on ``source.stat().st_size`` (closes major S-003).
        - Stage privately (LLR-155.1) via :func:`_private_stage_dir`: both
          ``temp`` and ``temp/.staging`` reparse-checked, then copy the
          source into a ``tempfile.mkdtemp`` directory under
          ``temp/.staging/`` — the source is only read, never
          moved, renamed or deleted.
        - Reuse a non-empty byte-identical target (bug B8) that is not a
            link or reparse point (security finding S-F4); race-freeness
            rests on the immutability invariant (LLR-155.3 as amended by
            LED .7) — no in-app writer replaces or deletes a placed file —
          not on a narrower check window. Otherwise claim the requested
          name — or the next free ``_<N>`` — with
          ``os.open(O_CREAT|O_EXCL|O_WRONLY)``, after an ``os.lstat`` of
          the candidate: a name taken by ANY type — file, directory, link,
          dangling link or junction — counts as taken on every platform,
          because on Windows a bare ``O_EXCL`` open FOLLOWS a dangling
          symlink and would create the claim at the link's target outside
          the work area (security finding S-F1; review finding F1). The
          claim is then re-verified with ``os.lstat`` to be a regular file
          and no reparse point, and filled with
          ``os.replace``, retrying a ``PermissionError`` up to 5 times within
          1 s before removing the own claim and raising
          ``WorkareaPlacementError``.
        - Remove the own staging directory in a ``finally`` tracked by an
          ownership flag set right after ``mkdtemp``.

    Dependencies:
        Uses:
            - shutil.copy2 / shutil.rmtree
            - tempfile.mkdtemp
            - os.open / os.replace / os.unlink
            - _is_reparse_point
            - _path_traverses_reparse_point
            - _find_workarea_root
        Used by:
            - s19_app.tui.app.S19TuiApp (project save and temp-load paths)
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

    resolved_destination = destination.resolve()
    workarea_root = _find_workarea_root(resolved_destination)
    if workarea_root is None or not resolved_destination.is_relative_to(workarea_root):
        raise WorkareaContainmentError(
            "Refusing to copy: destination is not contained inside "
            f"<base>/{WORKAREA_DIRNAME}/{WORKAREA_SUBDIR}/: {resolved_destination}"
        )

    # Walk every parent of ``destination`` from the workarea root downwards. Path.resolve()
    # silently follows reparse points, so a junction anywhere in the chain must be flagged
    # explicitly via os.lstat() + FILE_ATTRIBUTE_REPARSE_POINT (security finding S-N01).
    if _path_traverses_reparse_point(resolved_destination, stop_at=workarea_root.parent):
        raise WorkareaContainmentError(
            f"Refusing to copy: destination traverses a symbolic link or reparse point: {resolved_destination}"
        )

    size = resolved_source.stat().st_size
    if size > max_size_bytes:
        raise WorkareaContainmentError(
            f"Refusing to copy: source size {size} bytes exceeds cap {max_size_bytes} bytes: {resolved_source}"
        )

    resolved_destination.mkdir(parents=True, exist_ok=True)

    # Private staging (LLR-155.1): the reparse-checked shared staging home,
    # factored into one helper so every work-area writer stages the same way.
    stage_dir = _private_stage_dir(workarea_root)
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
        staged_bytes = staged_file.read_bytes()

        # Exclusive, atomic placement (LLR-155.2): claim the final name with
        # O_CREAT|O_EXCL, taking the next free ``_<N>`` whenever the requested
        # name is taken, and fill the claim with os.replace. The source is
        # only ever read, never moved, renamed or deleted.
        stem = resolved_source.stem
        suffix = resolved_source.suffix
        target = resolved_destination / resolved_source.name
        claim_path: Optional[Path] = None
        claim_owned = False
        counter = 0
        while claim_path is None:
            candidate = (
                target
                if counter == 0
                else resolved_destination / f"{stem}_{counter}{suffix}"
            )
            counter += 1
            if candidate == target:
                # Content dedup (bug B8), race-free by an INVARIANT
                # (LLR-155.3, amended by LED .7 — not by a narrower window:
                # reading twice cannot close the check-and-reuse race): no
                # in-app code path replaces or deletes a file at a final
                # name except this placement claiming a free name, so a
                # placed file is immutable once placed.
                # ``project_gather_service``'s delete-and-recopy
                # (:290-299) is the one known violator of the invariant,
                # converted by Inc 3b. A 0-byte target is NEVER reused — it
                # may be another writer's claim placeholder (PDR C1(a)),
                # and a target that is a link or reparse point is never
                # reused either — its bytes live outside the work area
                # (security finding S-F4).
                try:
                    if (
                        not _is_reparse_point(candidate)
                        and candidate.exists()
                        and candidate.stat().st_size > 0
                    ):
                        if candidate.read_bytes() == staged_bytes:
                            return candidate
                except OSError:
                    # an unreadable target is not trusted; claim a fresh name
                    pass
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
                claim_path = None
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
        return claim_path
    finally:
        # only ever the staging this call created (LLR-155.1/155.7)
        if staging_owned:
            shutil.rmtree(stage_dir, ignore_errors=True)


def place_group_into_workarea(
    sources: Sequence[Path],
    destination: Path,
    *,
    max_size_bytes: Optional[int] = None,
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
        destination (Path): Target directory. Must resolve under
            ``<base>/.s19tool/workarea/`` and must not traverse a symlink
            or NTFS junction.
        max_size_bytes (Optional[int]): Maximum permitted size per member,
            in bytes. ``None`` (the default) applies
            :data:`DEFAULT_COPY_SIZE_CAP_BYTES`, matching
            :func:`copy_into_workarea`.

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
        - Resolve ``destination``, locate its workarea root, and run the
          reparse-point walk — the exact checks ``copy_into_workarea``
          runs (LLR-155's seam, C3(e)).
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
            - _is_reparse_point / _path_traverses_reparse_point
            - _find_workarea_root / _private_stage_dir
        Used by:
            - s19_app.tui.segment_split_view.write_split_join_export
              (the BIN/``.addr`` pair; single files ride
              :func:`copy_into_workarea`)
    """
    resolved_destination = destination.resolve()
    workarea_root = _find_workarea_root(resolved_destination)
    if workarea_root is None or not resolved_destination.is_relative_to(workarea_root):
        raise WorkareaContainmentError(
            "Refusing to place: destination is not contained inside "
            f"<base>/{WORKAREA_DIRNAME}/{WORKAREA_SUBDIR}/: {resolved_destination}"
        )
    if _path_traverses_reparse_point(resolved_destination, stop_at=workarea_root.parent):
        raise WorkareaContainmentError(
            "Refusing to place: destination traverses a symbolic link or reparse point: "
            f"{resolved_destination}"
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

    resolved_destination.mkdir(parents=True, exist_ok=True)

    # Private staging (LLR-155.1): the same reparse-checked staging home
    # copy_into_workarea stages under.
    stage_dir = _private_stage_dir(workarea_root)
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
