from __future__ import annotations

import logging
import shutil
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


WORKAREA_DIRNAME = ".s19tool"
WORKAREA_SUBDIR = "workarea"
WORKAREA_TEMP = "temp"
LOGS_SUBDIR = "logs"
LOG_FILENAME = "s19tui.log"
S19_EXTENSIONS = {".s19", ".srec"}
HEX_EXTENSIONS = {".hex", ".ihex"}
MAC_EXTENSIONS = {".mac"}
A2L_EXTENSIONS = {".a2l"}
SUPPORTED_EXTENSIONS = S19_EXTENSIONS | HEX_EXTENSIONS | MAC_EXTENSIONS
PROJECT_DATA_EXTENSIONS = SUPPORTED_EXTENSIONS


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


def copy_into_workarea(source: Path, destination: Path) -> Path:
    """Copy a file into a target directory, avoiding name collisions."""
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / source.name
    if target.exists():
        stem = source.stem
        suffix = source.suffix
        counter = 1
        while True:
            candidate = destination / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1
    shutil.copy2(source, target)
    return target


def sanitize_project_name(name: str) -> Optional[str]:
    """Return a filesystem-safe project name or None if empty after cleaning."""
    cleaned = "".join(ch for ch in name.strip() if ch.isalnum() or ch in {"-", "_"})
    return cleaned if cleaned else None


def validate_project_files(project_dir: Path) -> tuple[list[Path], list[Path], Optional[str]]:
    """Return (data_files, a2l_files, error_message) enforcing project rules."""
    data_files = []
    a2l_files = []
    for item in project_dir.iterdir():
        if not item.is_file():
            continue
        suffix = item.suffix.lower()
        if suffix in PROJECT_DATA_EXTENSIONS:
            data_files.append(item)
        elif suffix in A2L_EXTENSIONS:
            a2l_files.append(item)
    if len(data_files) > 1:
        return data_files, a2l_files, "Project already has more than one S19/HEX/MAC file."
    if len(a2l_files) > 1:
        return data_files, a2l_files, "Project already has more than one A2L file."
    return data_files, a2l_files, None


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
