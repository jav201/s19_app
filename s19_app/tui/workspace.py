from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Sequence

from .models import ProjectVariantSet, VariantDescriptor


WORKAREA_DIRNAME = ".s19tool"
WORKAREA_SUBDIR = "workarea"
WORKAREA_TEMP = "temp"
LOGS_SUBDIR = "logs"
LOG_FILENAME = "s19tui.log"
# Default size cap for ``copy_into_workarea``. Cap rationale (per security
# Finding S-N02): realistic A2L upper end is ~100 MB per
# ``tests/conftest.py`` generators; 256 MB leaves ~2.5x headroom. The cap is
# configurable per call to allow regression testing.
DEFAULT_COPY_SIZE_CAP_BYTES = 256 * 1024 * 1024


class WorkareaContainmentError(ValueError):
    """Raised when ``copy_into_workarea`` rejects an unsafe source or destination."""


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
    (workarea_root / LOGS_SUBDIR).mkdir(parents=True, exist_ok=True)
    return workarea


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

    handler_exists = False
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler):
            if getattr(handler, "baseFilename", None) == str(log_path):
                handler_exists = True
                break

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
        Path: Absolute path of the file written inside ``destination``. Name collisions are
            resolved by appending ``_<N>`` before the suffix.

    Raises:
        WorkareaContainmentError: When ``destination`` is not contained inside a
            ``.s19tool/workarea/`` root, when ``source`` or ``destination`` (or any traversed
            parent of ``destination``) is a symbolic link or NTFS reparse point, or when
            ``source`` exceeds ``max_size_bytes``. Closes Phase 2 blockers S-001, S-002.
        FileNotFoundError: When ``source`` does not exist.

    Data Flow:
        - Resolve ``source`` and ``destination`` to absolute paths.
        - Reject reparse-point sources directly; reject when the destination, or any
          parent of the destination up to its workarea root, is a reparse point. ``Path.resolve``
          alone is not sufficient on Windows (per security finding S-N01).
        - Locate the ``.s19tool/workarea`` ancestor of ``destination``; reject when missing
          (closes blocker S-001).
        - Enforce ``max_size_bytes`` on ``source.stat().st_size`` (closes major S-003).
        - Create the destination directory and copy the source, deduplicating the filename
          on collision.

    Dependencies:
        Uses:
            - shutil.copy2
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
    target = resolved_destination / resolved_source.name
    if target.exists():
        stem = resolved_source.stem
        suffix = resolved_source.suffix
        counter = 1
        while True:
            candidate = resolved_destination / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1
    shutil.copy2(resolved_source, target)
    return target


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
            ``active_id`` resolved per the rule above.

    Raises:
        ValueError: When ``active_id`` is given but does not match any
            variant id (e.g. a stale manifest override, LLR-006.1).

    Data Flow:
        - Filter ``data_files`` to S19/HEX suffixes.
        - Sort by ``(name.lower(), name)`` (LLR-005.1 order) and wrap each
          path in a ``VariantDescriptor`` (``variant_id`` = filename stem).
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
    variants = tuple(
        VariantDescriptor(
            variant_id=item.stem,
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
